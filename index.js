'use strict';

const AWS = require( 'aws-sdk' );
const crypto = require( 'crypto' );
const extend = require( 'extend' );

const CIPHER = 'aes256';

const processor = {
    kms: null,

    options: {
        aws_kms_key_id: null,

        key_id_field: 'id',

        keystore: {
            get: () => {
                throw new Error( 'requires valid key storage' );
            },

            put: () => {
                throw new Error( 'requires valid key storage' );
            }
        },

        fields: {
            hash: [],
            pass: []
        }
    },

    _encrypt: function( key, plaintext, encoding = 'base64' ) {
        const cipher = crypto.createCipher( CIPHER, new Buffer( key, 'base64' ) );
        return ( Buffer.concat( [ cipher.update( plaintext, encoding ), cipher.final() ] ) ).toString( 'base64' );
    },

    _decrypt: function( key, ciphertext, encoding = 'base64' ) {
        const decipher = crypto.createDecipher( CIPHER, new Buffer( key, 'base64' ) );
        return ( Buffer.concat( [ decipher.update( ciphertext, encoding ), decipher.final() ] ) ).toString( 'base64' );
    },

    _get_owner_key: async function( object ) {
        let owner_key = await this.options.keystore.get( object[ this.options.key_id_field ] );
        if ( !owner_key ) {
            const owner_data_key = await this.kms.generateDataKey( {
                KeyId: this.options.aws_kms_key_id,
                KeySpec: 'AES_256'
            } ).promise();

            owner_key = {
                id: object[ this.options.key_id_field ],
                aws_kms_key_id: this.options.aws_kms_key_id,
                encrypted: owner_data_key.CiphertextBlob.toString( 'base64' ),
                created_at: new Date().toISOString()
            };

            await this.keystore.put( owner_key );
        }

        const decrypted = await this.kms.decrypt( {
            CiphertextBlob: new Buffer( owner_key.encrypted, 'base64' )
        } ).promise();

        if ( decrypted.KeyId !== this.options.aws_kms_key_id ) {
            throw new Error( 'mismatched aws kms parent key ids' );
        }

        owner_key.plaintext = decrypted.Plaintext.toString( 'base64' );

        return owner_key;
    },

    _get_data_key: async function( object ) {
        const owner_key = await this._get_owner_key( object );
        const random_key = crypto.randomBytes( 32 ).toString( 'base64' );
        const encrypted_random_key = this._encrypt( owner_key.plaintext, random_key );
        return {
            encrypted: encrypted_random_key,
            plaintext: random_key,
            owner_key: owner_key,
            created_at: new Date().toISOString()
        };
    },

    hash: function( value ) {
        return ( typeof value !== 'undefined' && value !== null ) ? crypto.createHash( 'sha256' ).update( value, 'utf8' ).digest( 'base64' ) : value;
    },

    encrypt: async function( object ) {
        const stringified_object = JSON.stringify( object );
        const data_key = await this._get_data_key( object );
        const encrypted_object = this._encrypt( data_key.plaintext, stringified_object, 'utf8' );

        return {
            _encrypted: encrypted_object,
            _encrypted_data_key: data_key.encrypted,
            _encrypted_owner_key: owner_key.encrypted
        };
    },

    decrypt: async function( encrypted ) {
        const decrypted_owner_key = await this.kms.decrypt( {
            CiphertextBlob: new Buffer( encrypted._encrypted_owner_key, 'base64' )
        } ).promise();

        const owner_key_plaintext = decrypted_owner_key.Plaintext.toString( 'base64' );
        const data_key_plaintext = this._decrypt( owner_key_plaintext, encrypted._encrypted_data_key );
        const data_plaintext = this._decrypt( data_key_plaintext, encrypted._encrypted );
        const decrypted = JSON.parse( data_plaintext );
        return decrypted;
    },

    serialize: async function( object, options ) {
        const encrypted = await this.encrypt( object );
        const processed = extend( true, {}, encrypted );

        // TODO: use traverse for better control?

        this.options.fields.hash.forEach( field => {
            processed[ field ] = this.hash( object[ field ] );
        } );

        this.options.fields.pass.forEach( field => {
            processed[ field ] = object[ field ];
        } );

        return processed;
    },

    deserialize: async function( processed, options ) {
        const decrypted = await this.decrypt( processed );
        const object = extend( true, {}, decrypted );

        return object;
    }
};

module.exports = {
    create: options => {

        const _processor = extend( true, {}, processor );
        _processor.options = extend( true, {}, processor.options, options );

        _processor.kms = new AWS.KMS( extend( true, {
            apiVersion: '2014-11-01'
        }, _processor.options.kms ) );

        delete _processor.options.kms;

        return _processor;
    }
};
