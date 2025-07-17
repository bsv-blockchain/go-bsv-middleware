# GO BSV Middleware

This project aims to build a middleware layer integrating mutual authentication and payment flows into the BSV ecosystem using the go-sdk.

The GO BSV Middleware is based on the following BSV specifications:
1. [BRC-103: Peer-to-Peer Mutual Authentication and Certificate Exchange Protocol](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0103.md)
2. [BRC-104: HTTP Transport for BRC-103 Mutual Authentication](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0104.md)

## Project Roadmap

The project is in development and follows a phased approach, focusing first on transport adapters, followed by authentication and payment middleware, and concluding with integration and documentation.
You can see the whole roadmap [here](./ROADMAP.md).

## Contribution Guidelines

We're always looking for contributors to help us improve the SDK. Whether it's bug reports, feature requests, or pull requests - all contributions are welcome.

1. **Fork & Clone**: Fork this repository and clone it to your local machine.
2. **Set Up**: Run `go mod tidy` to install all dependencies.
3. **Make Changes**: Create a new branch and make your changes.
4. **Test**: Ensure all tests pass by running `go test ./...`.
5. **Regression Tests**: Ensure compatibility with typescript client by running
   `go test -tags regressiontest ./pkg/internal/regressiontests/...`
   * For a detailed guide on regression tests, see [Regression Tests Guide](./pkg/internal/regressiontests/README.md)
6. **Commit**: Commit your changes and push to your fork.
7. **Pull Request**: Open a pull request from your fork to this repository.
   For more details, check the [contribution guidelines](./CONTRIBUTING.md).

## Support & Contacts

For questions, bug reports, or feature requests, please open an issue on GitHub.

## License

The license for the code in this repository is the Open BSV License. Refer to [LICENSE.txt](./LICENSE) for the license text.

Thank you for being a part of the BSV Blockchain Libraries Project. Let's build the future of BSV Blockchain together!
