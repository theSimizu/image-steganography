import { Router } from 'express'
import { placeholder, index, extract, extMsg } from '../controllers'
import multer from 'multer'

const router = Router()

const storage = multer.memoryStorage() // Store the file in memory as a buffer
const upload = multer({ storage })

router.post('/upload', upload.single('file'), placeholder)
router.post('/extract', upload.single('file'), extMsg)



router.get('/', index)

router.get('/extract', extract)

export default router

