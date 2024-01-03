import { Router } from 'express'
import { hideMessage, index, extract, extractMessage } from '../controllers'
import multer from 'multer'

const router = Router()

const storage = multer.memoryStorage() // Store the file in memory as a buffer
const upload = multer({ storage })

router.post('/upload', upload.fields([{name: 'msg', maxCount: 1}, {name: 'img', maxCount: 1}]), hideMessage)
router.post('/extract', upload.single('file'), extractMessage)



router.get('/', index)

router.get('/extract', extract)

export default router

