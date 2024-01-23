import axios from 'axios'
import fs from 'fs'
import { constructDTUrl, apiKey } from './dt'
import FormData from 'form-data'
import type { Store } from './generateSbom'
import runShellCommand from './helper/runShellCommand'

export type GrypeResult = {
	matches: {
		vulnerability: {
			id: string
		},
		artifact: {
			name: string,
			version: string
		}
	}[]
}

export type TrivyResult = {
	Results?: [{
		Vulnerabilities?: {
			VulnerabilityID: string,
			PkgName: string,
			InstalledVersion: string,
		}[]
	}]
}

const grypeScan = async ([image, tag, digest, sbomPath]: Store[number]) => {
    const command = `grype --add-cpes-if-none -o json sbom:${sbomPath}`

    const result = await runShellCommand(command)

    fs.writeFileSync(`./results/grype/${image}_${tag}.json`, result)

    return
}

const trivyScan = async ([image, tag, digest, sbomPath]: Store[number]) => {
	const command = `trivy sbom ${sbomPath} --format json --output ./results/trivy/${image}_${tag}.json`

	await runShellCommand(command)

	return 
}

const pushToDependencyTrack = async ([image, tag, digest, sbomPath]: Store[number]) => {
	const minProperties = {
		"name": `${image}:${tag}`,
		"classifier": "CONTAINER",
		"properties": [],
		"tags": [],
		"active": true
	}
	
	const projectPutResult = await axios.put(constructDTUrl('project'), minProperties, {
		headers: {
			'X-Api-Key': apiKey
		}
	})

	const uuid = projectPutResult.data.uuid as string

	if (!uuid) {
		throw new Error('No uuid')
	}

	const formData = new FormData()
	formData.append('project', uuid)
	const fileBuffer = fs.readFileSync(sbomPath)
	formData.append('bom', fileBuffer, {
		filename: `${image}_${tag}.sbom.json`,
		contentType: 'application/json'
	})

	const bomPostResult = await axios.post(constructDTUrl('bom'), formData, {
		headers: {
			'X-Api-Key': apiKey,
			'Content-Type': 'multipart/form-data',
		}
	})

	const token = bomPostResult.data.token as string

	if (!token) {
		throw new Error('No token')
	}

	return {
		uuid,
		token
  	}
}

const main = async () => {
	const store = JSON.parse(fs.readFileSync('./store.json').toString()) as Store

	await Promise.all(store.map((i) => grypeScan([...i])))
	await Promise.all(store.map((i) => trivyScan([...i])))
	const allImagesWithDTInfo = await Promise.all(store.map(async (i) => [i[0], i[1], i[2], i[3], i[4] ? i[4] : (await pushToDependencyTrack([...i]))] as const))

	fs.writeFileSync('./store.json', JSON.stringify(allImagesWithDTInfo))
}

main()


