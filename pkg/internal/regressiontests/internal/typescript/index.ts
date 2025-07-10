import * as process from 'node:process';
import { authFetch } from './authfetch/call';

const resultIndicator = '==================RESULT===============';

async function main(): Promise<void> {
  const result = await authFetch();
  showResult(result);
}

// Run the main function
main().catch(error => {
  showErrorResult(error);
  process.exit(1);
});

function showErrorResult(error: any) {
  showResult({ error: error.message });
}

function showResult(result: any) {
  console.log(resultIndicator);
  console.log(JSON.stringify(result, null, 2));
}
