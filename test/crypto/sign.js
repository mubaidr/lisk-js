/*
 * Copyright © 2017 Lisk Foundation
 *
 * See the LICENSE file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with the Lisk Foundation,
 * no part of this software, including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */
import {
	signMessageWithSecret,
	signMessageWithTwoSecrets,
	verifyMessageWithPublicKey,
	verifyMessageWithTwoPublicKeys,
	printSignedMessage,
	signAndPrintMessage,
	encryptMessageWithSecret,
	decryptMessageWithSecret,
	signTransaction,
	multiSignTransaction,
	verifyTransaction,
	decryptPassphraseWithPassword,
	encryptPassphraseWithPassword,
} from '../../src/crypto/sign';

const transactionBytes = require('../../src/transactions/transactionBytes');
const convert = require('../../src/crypto/convert');
const keys = require('../../src/crypto/keys');
const hash = require('../../src/crypto/hash');

const makeInvalid = (str) => {
	const char = str[0] === '0' ? '1' : '0';
	return `${char}${str.slice(1)}`;
};

const changeLength = str => `${str}00`;

describe.only('sign', () => {
	const defaultSecret = 'minute omit local rare sword knee banner pair rib museum shadow juice';
	const defaultPrivateKey = '314852d7afb0d4c283692fef8a2cb40e30c7a5df2ed79994178c10ac168d6d977ef45cd525e95b7a86244bbd4eb4550914ad06301013958f4dd64d32ef7bc588';
	const defaultPublicKey = '7ef45cd525e95b7a86244bbd4eb4550914ad06301013958f4dd64d32ef7bc588';
	const defaultSecondSecret = 'second secret';
	const defaultSecondPrivateKey = '9ef4146f8166d32dc8051d3d9f3a0c4933e24aa8ccb439b5d9ad00078a89e2fc0401c8ac9f29ded9e1e4d5b6b43051cb25b22f27c7b7b35092161e851946f82f';
	const defaultSecondPublicKey = '0401c8ac9f29ded9e1e4d5b6b43051cb25b22f27c7b7b35092161e851946f82f';
	const defaultMessage = 'Some default text.';
	const defaultSignature = '974eeac2c7e7d9da42aa273c8caae8e6eb766fa29a31b37732f22e6d2e61e8402106849e61e3551ff70d7d359170a6198669e1061b6b4aa61997e26b87e3a704';
	const defaultSignedMessage = `${defaultSignature}536f6d652064656661756c7420746578742e`;
	const defaultDoubleSignedMessage = '725de8389b97c6c0a0367f47e5817cac0e8fcc107d7b73c3ce8013309de3b838db890ad241e68fe3f5df7ca3acf1403acc33494a19665a27eb4ac4d8b70d7102974eeac2c7e7d9da42aa273c8caae8e6eb766fa29a31b37732f22e6d2e61e8402106849e61e3551ff70d7d359170a6198669e1061b6b4aa61997e26b87e3a704536f6d652064656661756c7420746578742e';
	const doubleSignedMessageWithInvalidFirstSignature = '3d3ae18d11e1f5e43ff1947f7da881d4b95671a850f4994aced863bee68eccc34d1d2046d4622ddd006c2afcad072fbd4a45c0f53bf3092f5e2f5043d22f3d0d074eeac2c7e7d9da42aa273c8caae8e6eb766fa29a31b37732f22e6d2e61e8402106849e61e3551ff70d7d359170a6198669e1061b6b4aa61997e26b87e3a704536f6d652064656661756c7420746578742e';
	const defaultPrintedMessage = `
-----BEGIN LISK SIGNED MESSAGE-----
-----MESSAGE-----
${defaultMessage}
-----PUBLIC KEY-----
${defaultPublicKey}
-----SIGNATURE-----
${defaultSignedMessage}
-----END LISK SIGNED MESSAGE-----
`.trim();
	// const defaultPassword = 'myTotal53cr3t%&';

	let getTransactionBytesStub;
	let hexToBufferStub;
	let bufferToHexStub;
	let convertPrivateKeyEd2CurveStub;
	let convertPublicKeyEd2CurveStub;
	let getRawPrivateAndPublicKeyFromSecretStub;
	let getPrivateAndPublicKeyFromSecretStub;
	let getTransactionHashStub;
	let getSha256HashStub;

	beforeEach(() => {
		getTransactionBytesStub = sinon.stub(transactionBytes, 'getTransactionBytes');

		hexToBufferStub = sinon.stub(convert, 'hexToBuffer');
		hexToBufferStub.withArgs(defaultSignedMessage).returns(Buffer.from(defaultSignedMessage, 'hex'));
		hexToBufferStub.withArgs(defaultDoubleSignedMessage).returns(Buffer.from(defaultDoubleSignedMessage, 'hex'));
		hexToBufferStub.withArgs(defaultPublicKey).returns(Buffer.from(defaultPublicKey, 'hex'));
		hexToBufferStub.withArgs(defaultSecondPublicKey).returns(Buffer.from(defaultSecondPublicKey, 'hex'));
		hexToBufferStub.withArgs(changeLength(defaultPublicKey)).returns(Buffer.from(changeLength(defaultPublicKey), 'hex'));
		hexToBufferStub.withArgs(changeLength(defaultSecondPublicKey)).returns(Buffer.from(changeLength(defaultSecondPublicKey), 'hex'));
		hexToBufferStub.withArgs(makeInvalid(defaultSignedMessage)).returns(Buffer.from(makeInvalid(defaultSignedMessage), 'hex'));
		hexToBufferStub.withArgs(doubleSignedMessageWithInvalidFirstSignature).returns(Buffer.from(doubleSignedMessageWithInvalidFirstSignature, 'hex'));
		hexToBufferStub.withArgs(makeInvalid(defaultDoubleSignedMessage)).returns(Buffer.from(makeInvalid(defaultDoubleSignedMessage), 'hex'));

		bufferToHexStub = sinon.stub(convert, 'bufferToHex');
		bufferToHexStub
			.withArgs(naclInstance.from_hex(defaultSignedMessage))
			.returns(defaultSignedMessage);
		bufferToHexStub
			.withArgs(naclInstance.from_hex(defaultDoubleSignedMessage))
			.returns(defaultDoubleSignedMessage);

		convertPrivateKeyEd2CurveStub = sinon.stub(convert, 'convertPrivateKeyEd2Curve');
		convertPublicKeyEd2CurveStub = sinon.stub(convert, 'convertPublicKeyEd2Curve');

		getRawPrivateAndPublicKeyFromSecretStub = sinon.stub(keys, 'getRawPrivateAndPublicKeyFromSecret');
		getRawPrivateAndPublicKeyFromSecretStub
			.withArgs(defaultSecret)
			.returns({ privateKey: Buffer.from(defaultPrivateKey, 'hex') });
		getRawPrivateAndPublicKeyFromSecretStub
			.withArgs(defaultSecondSecret)
			.returns({ privateKey: Buffer.from(defaultSecondPrivateKey, 'hex') });

		getPrivateAndPublicKeyFromSecretStub = sinon.stub(keys, 'getPrivateAndPublicKeyFromSecret');
		getPrivateAndPublicKeyFromSecretStub
			.withArgs(defaultSecret)
			.returns({ privateKey: defaultPrivateKey, publicKey: defaultPublicKey });
		getPrivateAndPublicKeyFromSecretStub
			.withArgs(defaultSecondSecret)
			.returns({ privateKey: defaultSecondPrivateKey, publicKey: defaultSecondPublicKey });

		getTransactionHashStub = sinon.stub(hash, 'getTransactionHash');
		getSha256HashStub = sinon.stub(hash, 'getSha256Hash');
	});

	afterEach(() => {
		getTransactionBytesStub.restore();
		hexToBufferStub.restore();
		bufferToHexStub.restore();
		convertPrivateKeyEd2CurveStub.restore();
		convertPublicKeyEd2CurveStub.restore();
		getRawPrivateAndPublicKeyFromSecretStub.restore();
		getPrivateAndPublicKeyFromSecretStub.restore();
		getTransactionHashStub.restore();
		getSha256HashStub.restore();
	});

	describe('#signMessageWithSecret', () => {
		it('should create a signed message by a secret passphrase', () => {
			const signedMessage = signMessageWithSecret(defaultMessage, defaultSecret);
			(signedMessage).should.be.equal(defaultSignedMessage);
		});
	});

	describe('#verifyMessageWithPublicKey', () => {
		it('should output the original signed message', () => {
			const verification = verifyMessageWithPublicKey(defaultSignedMessage, defaultPublicKey);
			(verification).should.be.equal(defaultMessage);
		});

		it('should detect invalid publicKeys', () => {
			(verifyMessageWithPublicKey.bind(null, defaultSignedMessage, changeLength(defaultPublicKey)))
				.should.throw('Invalid publicKey, expected 32-byte publicKey');
		});

		it('should detect not verifiable signature', () => {
			(verifyMessageWithPublicKey.bind(null, makeInvalid(defaultSignedMessage), defaultPublicKey))
				.should.throw('Invalid signature publicKey combination, cannot verify message');
		});
	});

	describe('#signMessageWithTwoSecrets', () => {
		it('should create a message signed by two secret passphrases', () => {
			const signature = signMessageWithTwoSecrets(
				defaultMessage, defaultSecret, defaultSecondSecret,
			);

			(signature).should.be.equal(defaultDoubleSignedMessage);
		});
	});

	describe('#verifyMessageWithTwoPublicKeys', () => {
		it('should verify a message using two publicKeys', () => {
			const verified = verifyMessageWithTwoPublicKeys(
				defaultDoubleSignedMessage, defaultPublicKey, defaultSecondPublicKey,
			);

			(verified).should.be.equal(defaultMessage);
		});

		it('should throw on invalid first publicKey', () => {
			(verifyMessageWithTwoPublicKeys.bind(
				null, defaultDoubleSignedMessage, changeLength(defaultPublicKey), defaultSecondPublicKey,
			))
				.should.throw('Invalid first publicKey, expected 32-byte publicKey');
		});

		it('should throw on invalid second publicKey', () => {
			(verifyMessageWithTwoPublicKeys.bind(
				null, defaultDoubleSignedMessage, defaultPublicKey, changeLength(defaultSecondPublicKey),
			))
				.should.throw('Invalid second publicKey, expected 32-byte publicKey');
		});

		it('should throw on invalid primary signature', () => {
			(verifyMessageWithTwoPublicKeys.bind(
				null,
				doubleSignedMessageWithInvalidFirstSignature, defaultPublicKey, defaultSecondPublicKey,
			))
				.should.throw('Invalid signature for first publicKey, cannot verify message');
		});

		it('should throw on invalid secondary signature', () => {
			(verifyMessageWithTwoPublicKeys.bind(
				null, makeInvalid(defaultDoubleSignedMessage), defaultPublicKey, defaultSecondPublicKey,
			))
				.should.throw('Invalid signature for second publicKey, cannot verify message');
		});
	});

	describe('#printSignedMessage', () => {
		it('should wrap the signed message into a printed Lisk template', () => {
			const printedMessage = printSignedMessage(
				defaultMessage, defaultSignedMessage, defaultPublicKey,
			);
			(printedMessage).should.be.equal(defaultPrintedMessage);
		});
	});

	describe('#signAndPrintMessage', () => {
		it('should sign the message and wrap it into a printed Lisk template', () => {
			const signedAndPrintedMessage = signAndPrintMessage(defaultMessage, defaultSecret);
			(signedAndPrintedMessage).should.be.equal(defaultPrintedMessage);
		});
	});
//
// 	describe('#encryptMessageWithSecret', () => {
// 		const encryptedMessage = encryptMessageWithSecret(
// 			secretMessage, defaultSecret, defaultPublicKey,
// 		);
//
// 		it('should encrypt a message and not throw with expected parameters', () => {
// 			(encryptedMessage).should.be.ok().and.type('object');
// 		});
//
// 		it('encrypted message should have nonce and encrypted message hex', () => {
// 			(encryptedMessage).should.have.property('nonce');
// 			(encryptedMessage).should.have.property('encryptedMessage');
// 		});
// 	});
//
// 	describe('#decryptMessageWithSecret', () => {
// 		const encryptedMessage = encryptMessageWithSecret(
// 			secretMessage, defaultSecret, defaultPublicKey,
// 		);
//
// 		it('should be able to decrypt the message correctly with given receiver secret', () => {
// 			const decryptedMessage = decryptMessageWithSecret(
// 				encryptedMessage.encryptedMessage, encryptedMessage.nonce, defaultSecret, defaultPublicKey,
// 			);
//
// 			(decryptedMessage).should.be.ok();
// 			(decryptedMessage).should.be.equal(secretMessage);
// 		});
// 	});
//
// 	describe('signTransaction and verify', () => {
// 		describe('#signTransaction', () => {
// 			const keyPair = keys.getKeys(defaultSignatureFirstSecret);
// 			const expectedSignature = '05383e756598172785843f5f165a8bef3632d6a0f6b7a3429201f83e5d60a5b57faa1fa383c4f33bb85d5804848e5313aa7b0cf1058873bc8576d206bdb9c804';
// 			const transaction = {
// 				type: 0,
// 				amount: 1000,
// 				recipientId: '58191285901858109L',
// 				timestamp: 141738,
// 				asset: {},
// 				id: '13987348420913138422',
// 				senderPublicKey: keyPair.publicKey,
// 			};
// 			const alterTransaction = {
// 				type: 0,
// 				amount: '100',
// 				recipientId: '58191285901858109L',
// 				timestamp: 141738,
// 				asset: {},
// 				id: '13987348420913138422',
// 				senderPublicKey: keys.publicKey,
// 			};
// 			const signature = signTransaction(transaction, defaultSignatureFirstSecret);
// 			const alterSignature = signTransaction(alterTransaction, defaultSignatureFirstSecret);
// 			it('should sign a transaction', () => {
// 				(signature).should.be.equal(expectedSignature);
// 			});
//
// 			it('should not be equal signing a different transaction', () => {
// 				(alterSignature).should.not.be.eql(signature);
// 			});
// 		});
//
// 		describe('#verify', () => {
// 			const transactionForVerifyTwoSignatures = {
// 				type: 0,
// 				amount: '10',
// 				fee: 10000000,
// 				recipientId: '13356260975429434553L',
// 				senderPublicKey: '215b667a32a5cd51a94c9c2046c11fffb08c65748febec099451e3b164452bca',
// 				senderSecondPublicKey: '922fbfdd596fa78269bbcadc67ec2a1cc15fc929a19c462169568d7a3df1a1aa',
// 				timestamp: 39541109,
// 				asset: {},
// 				signature: 'e7027dbe9bb8ebcc1738c560fe0a09161d781d9bfc5df4e9b4ccba2d7a1febcd25ba663938c8d22d4902d37435be149cfb0fd69e7a59daf53469abe8f6509e0c',
// 				signSignature: 'e88b4bd56a80de3b15220bdf0d1df0aa024a7a127ef07b8dc36a4e12d50e8eb338bc61ebe510ab15839e23f073cffda2a8c8b3d1fc1f0db5eed114230ecffe0a',
// 				id: '6950565552966532158',
// 			};
//
// 			const transactionForVerifyOneSignature = {
// 				type: 0,
// 				amount: '10',
// 				fee: 10000000,
// 				recipientId: '13356260975429434553L',
// 				senderPublicKey: '215b667a32a5cd51a94c9c2046c11fffb08c65748febec099451e3b164452bca',
// 				timestamp: 39541109,
// 				asset: {},
// 				signature: 'e7027dbe9bb8ebcc1738c560fe0a09161d781d9bfc5df4e9b4ccba2d7a1febcd25ba663938c8d22d4902d37435be149cfb0fd69e7a59daf53469abe8f6509e0c',
// 				id: '6950565552966532158',
// 			};
// 			it('should verify a single signed transaction', () => {
// 				const verification = verifyTransaction(transactionForVerifyOneSignature);
// 				(verification).should.be.true();
// 			});
// 			it('should verify a second signed transaction', () => {
// 				const verification = verifyTransaction(
// 					transactionForVerifyTwoSignatures,
// 					'922fbfdd596fa78269bbcadc67ec2a1cc15fc929a19c462169568d7a3df1a1aa',
// 				);
// 				(verification).should.be.true();
// 			});
// 			it('should not verify a single signed tampered transaction', () => {
// 				transactionForVerifyOneSignature.amount = 20;
// 				const verification = verifyTransaction(transactionForVerifyOneSignature);
// 				(verification).should.be.false();
// 			});
// 			it('should not verify a second signed tampered transaction', () => {
// 				transactionForVerifyTwoSignatures.asset.data = '123';
// 				const verification = verifyTransaction(
// 					transactionForVerifyTwoSignatures,
// 					'922fbfdd596fa78269bbcadc67ec2a1cc15fc929a19c462169568d7a3df1a1aa',
// 				);
// 				(verification).should.be.false();
// 			});
// 			it('should throw if try to verify a second sign transaction without secondPublicKey', () => {
// 				(verifyTransaction.bind(null, transactionForVerifyTwoSignatures)).should.throw('Cannot verify signSignature without secondPublicKey.');
// 			});
// 		});
// 	});
//
// 	describe('#multiSignTransaction', () => {
// 		it('should signTransaction a multisignature transaction', () => {
// 			const expectedMultiSignature = '9eb6ea53f0fd5079b956625a4f1c09e3638ab3378b0e7847cfcae9dde5a67121dfc49b5e51333296002d70166d0a93d2f4b5eef9eae4e040b83251644bb49409';
// 			const multiSigtransaction = {
// 				type: 0,
// 				amount: 1000,
// 				recipientId: '58191285901858109L',
// 				timestamp: 141738,
// 				asset: {},
// 				senderPublicKey: '5d036a858ce89f844491762eb89e2bfbd50a4a0a0da658e4b2628b25b117ae09',
// 				signature: '618a54975212ead93df8c881655c625544bce8ed7ccdfe6f08a42eecfb1adebd051307be5014bb051617baf7815d50f62129e70918190361e5d4dd4796541b0a',
// 				id: '13987348420913138422',
// 			};
//
// 			const multiSignature = multiSignTransaction(multiSigtransaction, defaultSignatureFirstSecret);
// 			(multiSignature).should.be.eql(expectedMultiSignature);
// 		});
// 	});
//
// 	describe('#encryptPassphraseWithPassword', () => {
// 		it('should encrypt a text with a password', () => {
// 			const cipher = encryptPassphraseWithPassword(secretPassphrase, defaultPassword);
// 			(cipher).should.be.type('object').and.have.property('cipher').and.be.hexString();
// 			(cipher).should.be.type('object').and.have.property('iv').and.be.hexString().and.have.length(32);
// 		});
// 	});
//
// 	describe('#decryptPassphraseWithPassword', () => {
// 		it('should decrypt a text with a password', () => {
// 			const cipherAndNonce = {
// 				cipher: '1c527b9408e77ae79e2ceb1ad5907ec523cd957d30c6a08dc922686e62ed98271910ca5b605f95aec98c438b6214fa7e83e3689f3fba89bfcaee937b35a3d931640afe79c353499a500f14c35bd3fd08',
// 				iv: '89d0fa0b955219a0e6239339fbb8239f',
// 			};
// 			const decrypted = decryptPassphraseWithPassword(cipherAndNonce, defaultPassword);
// 			(decrypted).should.be.eql(secretPassphrase);
// 		});
// 	});
//
// 	describe('encrypting passphrase integration test', () => {
// 		it('should encrypt a given secret with a password and decrypt it back to the original passphrase', () => {
// 			const encryptedString = encryptPassphraseWithPassword(secretPassphrase, defaultPassword);
// 			const decryptedString = decryptPassphraseWithPassword(encryptedString, defaultPassword);
// 			(decryptedString).should.be.eql(secretPassphrase);
// 		});
// 	});
});
