import crypto from 'crypto'
import zlib from 'zlib'
import { spawn } from 'child_process'
import { Readable } from 'stream'

export function encryptString(text: string, password: string | Buffer, callback: Function) {
    crypto.randomBytes(64, (err, salt) => {
        if (err) return callback(err, null)
        crypto.pbkdf2(password, salt, 100001, 32, 'sha512', (err, key) => {
            if (err) return callback(err, null)
            crypto.randomBytes(16, (err, iv) => {
                if (err) return callback(err, null)
                const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
                let cipherText = cipher.update(text, 'utf8', 'hex')
                cipherText += cipher.final('hex')
                const cipherTextBuffer = Buffer.from(cipherText, 'hex')
                const tag = cipher.getAuthTag()
                const encryptedData = Buffer.concat([iv, salt, cipherTextBuffer, tag])
                
                return callback(null, encryptedData)
            })
        })
    })

}

function decryptString(encryptedData: Buffer, password: string, callback: Function) {
    const iv = encryptedData.subarray(0, 16)
    const salt = encryptedData.subarray(16, 80)
    const cipherTextBuffer = encryptedData.subarray(80, encryptedData.length-16)
    const tag = encryptedData.subarray(encryptedData.length-16)

    crypto.pbkdf2(password, salt, 100001, 32, 'sha512', (err, key) => {
        if (err) return callback(err, null)
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
        decipher.setAuthTag(tag)
        let decryptedData = decipher.update(cipherTextBuffer).toString('utf8')
        decryptedData += decipher.final('utf8')
        return callback(null, decryptedData)
    })

}

export function binaryToBuffer(bin: string) {
    let hex = ''
    for (const bits of bin.split(' ')) {
        const hexValue = parseInt(bits, 2).toString(16)
        hex += `${'0'.repeat(2-hexValue.length)}${hexValue}`
    }
    return Buffer.from(hex, 'hex')
}

function bufferToBinary(buffer: Buffer) {
    const bits: string[] = []
    const hexArray = Uint8Array.from(buffer)
    for (const value of hexArray) {
        const val = value.toString(2)
        bits.push(`${'0'.repeat(8-val.length)}${val}`)
    }
    return bits.join(' ')
}


export function encryptStringBin(text: string | Buffer, password: string | Buffer, callback: Function) {
    encryptString(text.toString(), password, (err: Error, encryptedData: Buffer) => {
        if (err) return callback(err, null)
        callback(null, bufferToBinary(encryptedData))
    })

}

export function decryptStringBin(encryptedData: string, password: string, callback: Function) {
    decryptString(binaryToBuffer(encryptedData), password, (err: Error, decryptedData: string) => {
        if (err) return callback(err, null)
        callback(null, decryptedData)
    })
}


