
### Bootstrap
The Bootstrap smart contract is designed to manage token whitelisting, operator registration, deposits, and withdrawals. It ensures that operations are locked during specific periods (before mainnet/testnet launch) for security. This contract is independent and will be upgraded after the mainnet/testnet launch.

### ExocoreGateway
The ExocoreGateway contract handles cross-chain messaging and interactions with the Exocore chain. It inherits from multiple contracts and interfaces, including PausableUpgradeable, OwnableUpgradeable, IExocoreGateway, ExocoreGatewayStorage, and OAppUpgradeable. This contract provides functionalities such as deposits, delegations, undelegations, and the withdrawal of principal and rewards. It facilitates cross-chain communication through the LayerZero protocol.

### ClientChainGateway
The ClientChainGateway contract acts as a cross-chain gateway, transmitting information and commands between the Exocore core layer and the client chain. It verifies and executes signed commands such as deposits, withdrawals, and delegation, manages whitelisted assets and their Vault deployments, allows stakers to interact with the core layer through events, and provides emergency pause and resume functions to ensure system stability.

### BaseRestakingController
The BaseRestakingController contract is an abstract contract that inherits from PausableUpgradeable, OAppSenderUpgradeable, IBaseRestakingController, and ClientChainGatewayStorage. It primarily handles the fundamental logic related to restaking, including declarations, delegations, undelegations, and messaging with the Exocore chain.

### LSTRestakingController
The LSTRestakingController contract provides functionalities for users to deposit tokens, withdraw principal from Exocore, and withdraw rewards from Exocore. It primarily handles operations related to Liquid Staking Tokens (LST). This contract inherits from PausableUpgradeable, ILSTRestakingController, and BaseRestakingController.

### NativeRestakingController
The NativeRestakingController contract primarily handles the logic for native Ethereum restaking. It includes functionalities such as staking, creating ExoCapsule contracts, and managing deposits and partial/full withdrawals for Beacon Chain validators. It is an abstract contract that inherits from PausableUpgradeable, INativeRestakingController, and BaseRestakingController.

### Vault
The Vault smart contract manages deposits, withdrawals, and balance updates for users interacting with the system. It ensures secure handling of ERC20 tokens and implements business logic to maintain accurate records of user balances, including principal and reward amounts.

### ExoCapsule
The ExoCapsule contract is designed to handle specific operations related to native Ethereum restaking tokens. It provides functionalities for depositing and withdrawing these tokens, ensuring secure and efficient management of virtual staked assets.
