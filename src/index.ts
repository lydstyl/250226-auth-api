import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import { PrismaClient } from '@prisma/client'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
const prisma = new PrismaClient()
const SECRET_KEY = process.env.SECRET_KEY || ''

app.use(express.json())

// Route d'inscription
app.post('/register', async (req, res) => {
  const { email, password, site, group } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)

  try {
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, site, group }
    })
    res.status(201).json({ message: 'User created', user })
  } catch (error) {
    res.status(400).json({ error: 'User already exists or invalid data' })
  }
})

// Route de connexion
type loginRequest = {
  body: {
    email: string
    password: string
    site: string
  }
}
app.post('/login', async (req: loginRequest, res: any) => {
  const { email, password, site } = req.body

  const user = await prisma.user.findUnique({ where: { email } })
  if (!user || user.site !== site) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const token = jwt.sign(
    { email: user.email, site: user.site, group: user.group },
    SECRET_KEY,
    { expiresIn: '1h' }
  )
  res.json({ token })
})

// Middleware de vérification du JWT
import { Request, Response, NextFunction } from 'express'

interface CustomRequest extends Request {
  user?: any
}

const authenticateJWT = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
): void => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) {
    res.sendStatus(403)
    return
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

app.get('/protected', authenticateJWT, (req: CustomRequest, res) => {
  res.json({ message: 'You have access', user: req.user })
})

app.listen(3000, () => console.log('Server running on port 3000'))
