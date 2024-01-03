import fs from 'fs'
import os from 'os'
import path from 'path'
import { Readable } from 'stream'
import { spawn } from 'child_process'
import { Request, Response } from 'express'


export async function index(req:Request, res:Response) {
    res.render('index')
}

export async function extract(req:Request, res:Response) {
    res.render('extract')
}

export async function extractMessage(req:Request, res:Response) {
    if (!req.file) return res.status(400).send('No file uploaded.')
    const pwd = req.body.pwd
    const fileBuffer = req.file.buffer
    const fileName = req.file.originalname.split('.').slice(0, -1).toString()

    const params = ['python/steg.py', 'extract', '-p', `${pwd}`]

    const pythonSteganography = spawn(`./python/venv/bin/python`, params)
    Readable.from(fileBuffer).pipe(pythonSteganography.stdin)
    
    res.set('Content-disposition', 'attachment; filename=' + `${fileName}.txt`)
    res.set('Content-Type', 'text/txt')

    pythonSteganography.stdout.pipe(res)
    pythonSteganography.on('error', (error) => console.log(`Error: ${error.message}`))
}

export async function hideMessage(req:Request, res:Response) {
    interface File {
        fieldname: string,
        originalname: string,
        encoding: string,
        mimetype: string,
        buffer: Buffer
        size: Number
    }
    const fifosDirectory = path.join(os.tmpdir(), 'myfifo-')
    // @ts-ignore
    const msgFile:File = req.files?.msg?.[0]
    // @ts-ignore
    const imgFile:File = req.files?.img[0]

    const msgText = req.body.msg
    const msgBuffer = msgFile?.buffer
    const pwds:Array<string> = req.body.pwd

    if (!imgFile) return res.status(400).send('No file uploaded.')
    if (!msgText && !msgBuffer) return res.status(400).send('No message uploaded.')
    if (pwds[0] != pwds[1]) return res.status(400).send('Different passwords')
    
    const pwd = pwds[0]
    const imageBuffer = imgFile.buffer
    const fileName = imgFile.originalname.split('.').slice(0, -1).toString()

    fs.mkdtemp(fifosDirectory, (err, directory) => {
        if (err) throw err

        const messagePipe = path.join(directory, 'message')
        spawn('mkfifo', [messagePipe])

        if (msgBuffer) Readable.from(msgBuffer).pipe(fs.createWriteStream(messagePipe))
        console.log(messagePipe)
        
        const params = ['python/steg.py', 
                        'embed',
                        '-m', `${msgText}`,
                        '-mf', `${messagePipe}`,
                        '-p', `${pwd}`]

        const pythonSteganography = spawn(`./python/venv/bin/python`, params)

        Readable.from(imageBuffer).pipe(pythonSteganography.stdin)

        res.set('Content-disposition', 'attachment; filename=' + `${fileName}.png`)
        res.set('Content-Type', 'image/png')
        
        const responseStream = pythonSteganography.stdout.pipe(res)

        responseStream.on('finish', () => {
            fs.rm(directory, {recursive: true, force: true}, (err) => {console.log(err)})
        })
        

    })

	
}


