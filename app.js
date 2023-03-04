require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem vindo a nossa API"})
})

// Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id, '-password')
    if(!user) {
        return res.status(404).json({msg: 'Usuario nao encontrado!'})
    }

    return res.status(200).json(user)
})

function checkToken(req, res, next){
    
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'Acesso negado!'})
    }

    try {
        
        const secret = process.env.SECRETE
        jwt.verify(token, secret)
        next()
        
    } catch (error) {
        res.status(400).json({ msg: 'Tokem inválido!'})
    }
}

// Register user
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmPassword} = req.body

    // Validations
    if(!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!'})
    }

    if(!email) {
        return res.status(422).json({ msg: 'O Email é obrigatório!'})
    }

    if(!password) {
        return res.status(422).json({ msg: 'A senha é obrigatório!'})
    }

    if(password != confirmPassword) {
        return res.status(422).json({ msg: "As senhas não são iguais"})
    }

    // check if user exist
    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({ msg: 'Usuario ja existe'})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create User
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()

        res.status(201).json({msg: "Usuario criado com sucesso!"})
    } catch (error) {
        res.status(500).json({msg: error})
    }

})

// Login in User
app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body

    //Validation
    if(!email) {
        return res.status(422).json({msg: 'O email e obrigatorio'})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha e obrigatorio.'})
    }

    // Check if user exists
    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(404).json({msg: "Usuario nao encontrado!"})
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({msg: 'Senha invalida!'})
    }

    try {
        const secret = process.env.SECRETE

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )
        res.status(200).json({ msg: "Autenticacao realizada com sucesso", token})
    } catch (error) {
        console.log(error)
    }
})
// credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.jkqzgim.mongodb.net/?retryWrites=true&w=majority`)
.then(() => {
    app.listen(3000) 
    console.log('Conectou ao banco de dados')

})
.catch((err) => console.log(err))


