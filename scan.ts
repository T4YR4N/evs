import axios from 'axios'
import fs, { read, writeFile } from 'fs'
import { constructDTUrl, apiKey } from './dt'
import FormData from 'form-data'
import { readStore, writeStore, type Store } from './store'
import runShellCommand from './helper/runShellCommand'
import commandLineParser from './commandLineParser'

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

const grypeScan = async ([image, tag, digest, sbomPath]: Store[number], arg: ReturnType<typeof commandLineParser>) => {
    const command = `grype --add-cpes-if-none -o json sbom:${sbomPath}`

    const result = await runShellCommand(command)

    fs.writeFileSync(`./results_${arg}/grype/${image}_${tag}.json`, result)

    return
}

const trivyScan = async ([image, tag, digest, sbomPath]: Store[number], arg: ReturnType<typeof commandLineParser>) => {
	const command = `trivy sbom ${sbomPath} --format json --output ./results_${arg}/trivy/${image}_${tag}.json`

	await runShellCommand(command)

	return 
}

const pushToDependencyTrack = async ([image, tag, digest, sbomPath]: Store[number], arg: ReturnType<typeof commandLineParser>) => {
	const minProperties = {
		"name": `${image}:${tag}_${arg}`,
		"classifier": "CONTAINER",
		"properties": [],
		"tags": [],
		"active": true
	}

	try {
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
	} catch (err) {
		console.log(`Error for ${image}:${tag}`)
		console.log(err)
	}
}

const main = async () => {
	const arg = commandLineParser()
	const store = readStore(arg)

	await Promise.all(store.map((i) => grypeScan([...i], arg)))
	await Promise.all(store.map((i) => trivyScan([...i], arg)))
	const allImagesWithDTInfo = await Promise.all(store.map(async (i) => [i[0], i[1], i[2], i[3], i[4] ? i[4] : (await pushToDependencyTrack([...i], arg))] as const))

	writeStore(arg, allImagesWithDTInfo)
}

main()


