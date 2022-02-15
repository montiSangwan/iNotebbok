const express = require('express');
const router = express.Router();

const Note = require('../models/Note');
const fetchuser = require('../middleware/fetchuser');
const { body, validationResult } = require('express-validator');  // to validate the name , email and password

//ROUTE 1 : Get all the notes using GET "/api/notes/fetchallnotes". Login required
router.get('/fetchallnotes', fetchuser, async (req, res)=>{
    try {
        const notes = await Note.find({user: req.user.id});
        res.json(notes);

    } catch (error) {
        console.error(error.message);
        res.send(500).send("Some error occured");
    }
    
})

//ROUTE 2 : Add a new note using POST "/api/notes/addnote". Login required
router.post('/addnote', fetchuser, [
        body('title', 'Enter a valid title').isLength({ min: 3 }),
        body('description', 'Enter a valid description').isLength({ min: 5 }),  
    ] , async (req, res)=>{
    
    try {
        // If there are errors, return Bad request and the errors
        const errors = validationResult(req); 
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const {title , description , tag} = req.body;  // Destructuring

        const note = new Note({
            title , description , tag , user : req.user.id
        })

        const savedNote = await note.save();
        res.json(savedNote);

    } catch (error) {
        console.error(error.message);
        res.send(500).send("Some error occured");
    } 
})

//ROUTE 3 : Update an existing Note using PUT "/api/notes/updatenote". Login required
router.put('/updatenote/:id', fetchuser , async (req, res)=>{
    const {title , description , tag} = req.body;

    try {
        // Create a newNote object
        const newNote = {};
        if(title){
            newNote.title = title
        }
        if(description){
            newNote.description = description
        }
        if(tag){
            newNote.tag = tag
        }

        // Find the note to be updated and update it
        let note = await Note.findById(req.params.id);  // :id
        if(!note){
            return res.status(404).send('Not Found');
        }

        // Allow updation only if user owns this note
        if(note.user.toString() !== req.user.id){
            return res.status(401).send('Not Allowed');
        }

        note = await Note.findByIdAndUpdate(req.params.id , {$set: newNote} , {new: true});
        res.json(note);

    } catch (error) {
        console.error(error.message);
        res.send(500).send("Some error occured");
    }
    
})

//ROUTE 4 : Delete an existing Note using DELETE "/api/notes/deletenote". Login required
router.delete('/deletenote/:id', fetchuser , async (req, res)=>{

    try {
        // Find the note to be deleted and delete it
        let note = await Note.findById(req.params.id);  // :id
        if(!note){
            return res.status(404).send('Not Found');
        }

        // Allow deletion only if user owns this note
        if(note.user.toString() !== req.user.id){
            return res.status(401).send('Not Allowed');
        }

        note = await Note.findByIdAndDelete(req.params.id);
        res.json({"Success": "Note has been deleted" , note: note});

    } catch (error) {
        console.error(error.message);
        res.send(500).send("Some error occured");
    }
    
})

module.exports = router