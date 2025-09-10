export function printHelp() {
    console.log(`Usage: node dist/client/client.js [options]

Options:
  --addr host:port        gRPC server address (default: localhost:50050)
  --url URL               Target URL to fetch (required)
  --method METHOD         HTTP method (default: GET)
  --header "K: V"         HTTP header (can be repeated)
  --body STRING           Request body string
  --retry N               Retry counter number
  --fresh                 Use fresh instance option (boolean)
  -h, --help              Show this help

Examples:
  npm run client -- --url https://example.com
  npm run client -- --url https://httpbin.org/anything --method POST --header "content-type: application/json" --body '{"hello":"world"}'
`);
}
