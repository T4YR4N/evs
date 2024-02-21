import { exec } from 'child_process'

const runShellCommand = (command: string): Promise<string> => {
	return new Promise((resolve, reject) => {
	  exec(command, {maxBuffer: 1024*1000*1000}, (error, stdout, stderr) => {
			if (error) {
				reject(`Error executing command: ${error.message}`);
				return;
			}
	
			// if (stderr) {
			//   reject(`Command stderr: ${stderr}, ${command}`);
			//   return;
			// }
	
			resolve(stdout);
		});
	});
}

export default runShellCommand