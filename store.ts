import fs from 'fs'
import commandLineParser from './commandLineParser'

/**
 * Store format:
 * [ image, tag, digest, sbomPath, DT-info ]
 */
export type Store = [string, string, string, string, {uuid: string, token: string}|undefined][]

export const readStore = (arg: 'trivy' | 'syft') => {
	const result = fs.readFileSync(`./store_${arg}.json`).toString()
	return JSON.parse(result) as Store
}

export const writeStore = (arg: ReturnType<typeof commandLineParser>, store: Store | Readonly<Store[number]>[]) => {
	fs.writeFileSync(`./store_${arg}.json`, JSON.stringify(store))
}
