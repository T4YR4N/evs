import fs from 'fs'
import type { ImagesFile, ResultFile, SbomsFile } from '../files'
import path from 'path'

export const readImageFile = (pathName: string): ImagesFile => {
	if (!pathName.endsWith('.images.json')) throw new Error('Invalid file type')

	const images = JSON.parse(fs.readFileSync(pathName).toString()) as ImagesFile

	return images
}

export const writeSbomsFile = (pathName: string, contents: SbomsFile) => {
	if (!pathName.endsWith('.sboms.json')) throw new Error('Invalid file type')

	fs.writeFileSync(pathName, JSON.stringify(contents))
}

export const readSbomsFile = (pathName: string): SbomsFile => {
	if (!pathName.endsWith('.sboms.json')) throw new Error('Invalid file type')

	const boms = JSON.parse(fs.readFileSync(pathName).toString()) as SbomsFile

	return boms
}

export const writeSbomFile = (pathName: string, contents: string) => {
	if (!pathName.endsWith('.sbom.json')) throw new Error('Invalid file type')

	const directoryPath = path.dirname(pathName);

	if (!fs.existsSync(directoryPath)) {
		console.log(`Creating directory: ${directoryPath}`)
		fs.mkdirSync(directoryPath, { recursive: true })
	}

	fs.writeFileSync(pathName, contents)
}

export const writeArbitraryFile = (pathName: string, contents: string) => {
	const directoryPath = path.dirname(pathName);

	if (!fs.existsSync(directoryPath)) {
		console.log(`Creating directory: ${directoryPath}`)
		fs.mkdirSync(directoryPath, { recursive: true })
	}

	fs.writeFileSync(pathName, contents)
}

export const writeResultFile = (pathName: string, contents: ResultFile) => {
	if (!pathName.endsWith('.results.json')) throw new Error('Invalid file type')

	const directoryPath = path.dirname(pathName)

	if (!fs.existsSync(directoryPath)) {
		console.log(`Creating directory: ${directoryPath}`)
		fs.mkdirSync(directoryPath, { recursive: true })
	}

	fs.writeFileSync(pathName, JSON.stringify(contents))
}

export const readResultFile = (pathName: string): ResultFile => {
	if (!pathName.endsWith('.results.json')) throw new Error('Invalid file type')

	const results = JSON.parse(fs.readFileSync(pathName).toString()) as ResultFile

	return results
}