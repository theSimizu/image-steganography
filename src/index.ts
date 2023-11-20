import path from 'path'
import helmet from 'helmet'
import logger from 'morgan'
import process from 'process'
import express from 'express'
import compression from 'compression'
import cookieParser from 'cookie-parser'
import indexRouter from './routes/indexRoute'

const port =  process.argv[2] || 3000

const app = express()

// View engine setup
app.set('views', path.join(__dirname, '../views'))
app.set('view engine', 'ejs')

// Middlewares
app.use(helmet())
app.use(logger('dev'))
app.use(express.json())
app.use(cookieParser())
app.use(express.static('./public'))
app.use(express.urlencoded({ extended: false }))
app.use(compression())

// Routers
app.use('/', indexRouter)

app.listen(port, () => console.log(`Listening on port ${port}`))

