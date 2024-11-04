package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"bytes"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	Password  string
	DSSignKey userlib.DSSignKey
	PKEDecKey userlib.PKEDecKey
	SourceKey []byte // from slow hash password, use to derived other key
}

// NOTE: The following methods have toy (insecure!) implementations.
type Authentication struct {
	EncData  []byte
	HMACData []byte
}

type RSAAuthentication struct {
	Enc_sharer_username  []byte
	Sig_share_username   []byte
	Enc_file_struct_uuid []byte
	Sig_file_struct_uuid []byte
	Enc_keyA             []byte
	Sig_keyA             []byte
	Enc_file_key_uuid    []byte
	Sig_file_key_uuid    []byte
}

/*
InitUser initializes a new user with the provided username and password.
It performs various checks to ensure the username is unique, creates user keys for encryption and authentication,
generates public and private keys for the user, and securely stores user data.
If successful, it returns a pointer to the created User struct and nil error.
If any error occurs during the initialization process, it returns nil and the corresponding error.
*/

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check for empty username error
	if username == "" {
		err = errors.New("username cannot be empty error")
		return nil, err
	}

	// check for username existed error
	user_struct_uuid := usernameToUUID(username, "user-struct")
	_, ok := userlib.DatastoreGet(user_struct_uuid)
	if ok {
		err = errors.New("user already existed")
		return nil, err
	}

	username_password_uuid := usernameToUUID(username, "password")
	_, ok = userlib.DatastoreGet(username_password_uuid)
	if ok {
		err = errors.New("user already existed")
		return nil, err
	}

	/* ######## Creating new user ######## */

	// Link username password

	source_key := createSourceKey(username, password)
	enc_argon2_key := createKeys(source_key, "enc-argon2-key")
	enc_argon2_password := userlib.SymEnc(enc_argon2_key, userlib.RandomBytes(16), source_key)
	hmac_argon2_key := createKeys(source_key, "hmac-argon2-key")
	hmac_argon2_password, err := userlib.HMACEval(hmac_argon2_key, enc_argon2_password)
	if err != nil {
		return nil, errors.New("hmac argon2 password error: " + err.Error())
	}
	var source_key_EH Authentication
	source_key_EH.EncData = enc_argon2_password
	source_key_EH.HMACData = hmac_argon2_password
	source_key_marshal, err := json.Marshal(source_key_EH)
	if err != nil {
		return nil, errors.New("Marshal source key EncHMAC err: " + err.Error())
	}
	userlib.DatastoreSet(username_password_uuid, source_key_marshal)

	// Create user pulic keys

	// Sign Key
	ds_sign_key, ds_verify_key, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("DSKey generation error: " + err.Error())
	}
	err = userlib.KeystoreSet(username+"/verify-key", ds_verify_key)
	if err != nil {
		return nil, errors.New("cannot set verify key: " + err.Error())
	}

	// RSA Key
	rsa_pub_key, rsa_priv_key, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("RSAKey generation error: " + err.Error())
	}
	err = userlib.KeystoreSet(username+"/rsa-pub", rsa_pub_key)
	if err != nil {
		return nil, errors.New("cannot set public key: " + err.Error())
	}

	var userdata User
	userdata.Username = username
	userdata.Password = password
	userdata.DSSignKey = ds_sign_key
	userdata.PKEDecKey = rsa_priv_key
	userdata.SourceKey = source_key

	// Store the encrypt of userdata
	marshal_userdata, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("marshal user struct error: " + err.Error())
	}

	enc_user_struct_key := createKeys(source_key, "enc-marshal-user-struct")
	enc_user_struct := userlib.SymEnc(enc_user_struct_key, userlib.RandomBytes(16), marshal_userdata)

	hmac_user_struct_key := createKeys(source_key, "hmac-marshal-user-struct")
	hmac_user_struct, err := userlib.HMACEval(hmac_user_struct_key, enc_user_struct)
	if err != nil {
		return nil, errors.New("hmac user struct error: " + err.Error())
	}

	var auth Authentication
	auth.EncData = enc_user_struct
	auth.HMACData = hmac_user_struct
	marshal_auth, err := json.Marshal(auth)
	if err != nil {
		return nil, errors.New("Marshal user_struct's auth error: " + err.Error())
	}
	userlib.DatastoreSet(user_struct_uuid, marshal_auth)

	return &userdata, nil
}

/*
GetUser retrieves user data based on the provided username and password.
It verifies the existence of the user, validates the provided password,
checks for data integrity, and decrypts the user's information securely.
If successful, it returns a pointer to the User struct containing the user's data and nil error.
If any error occurs during the retrieval process, it returns nil and the corresponding error.
*/

func GetUser(username string, password string) (userdataptr *User, err error) {
	// check if username exist
	user_struct_uuid := usernameToUUID(username, "user-struct")
	marshal_user_struct_auth, ok := userlib.DatastoreGet(user_struct_uuid)
	if !ok {
		return nil, errors.New("User does not exist error")
	}

	// check if the authetnication is correct
	username_password_uuid := usernameToUUID(username, "password")
	marshal_auth, ok := userlib.DatastoreGet(username_password_uuid)
	if !ok {
		return nil, errors.New("User does not exist error ")
	}
	var username_password_auth Authentication
	err = json.Unmarshal(marshal_auth, &username_password_auth)
	if err != nil {
		return nil, errors.New("Unmarshal user's authentication error: " + err.Error())
	}

	source_key := createSourceKey(username, password)
	enc_argon2_key := createKeys(source_key, "enc-argon2-key")
	// check if the password match
	password_copy := userlib.SymDec(enc_argon2_key, username_password_auth.EncData)
	valid_password := bytes.Equal(password_copy, source_key[:16])
	if !valid_password {
		return nil, errors.New("invalid username or password")
	}

	// check for tampered data
	hmac_argon2_key := createKeys(source_key, "hmac-argon2-key")
	hmac_argon2_password, err := userlib.HMACEval(hmac_argon2_key, username_password_auth.EncData)
	if err != nil {
		return nil, errors.New("HMAC generated error: " + err.Error())
	}
	auth_valid := userlib.HMACEqual(hmac_argon2_password, username_password_auth.HMACData)
	if !auth_valid {
		return nil, errors.New("tampered user's authentication")
	}

	// Unmarshal user struct auth
	var user_struct_auth Authentication
	err = json.Unmarshal(marshal_user_struct_auth, &user_struct_auth)
	if err != nil {
		return nil, errors.New("Unmarshal user struct authentication error: " + err.Error())
	}

	// check for tampered data
	hmac_user_struct_key := createKeys(source_key, "hmac-marshal-user-struct")
	hmac_marshal_user_struct, err := userlib.HMACEval(hmac_user_struct_key, user_struct_auth.EncData)
	if err != nil {
		return nil, errors.New("HMAC generated error: " + err.Error())
	}
	valid_data := userlib.HMACEqual(hmac_marshal_user_struct, user_struct_auth.HMACData)
	if !valid_data {
		return nil, errors.New("tampered user struct authentication")
	}

	// Decrypt user struct
	enc_user_struct_key := createKeys(source_key, "enc-marshal-user-struct")
	marshal_user_struct := userlib.SymDec(enc_user_struct_key, user_struct_auth.EncData)

	var userdata User
	err = json.Unmarshal(marshal_user_struct, &userdata)
	if err != nil {
		return nil, errors.New("Unmarshal user-struct err: " + err.Error())
	}
	userdataptr = &userdata
	return userdataptr, nil
}

type FileStruct struct {
	Owner     string
	OwnerSig  []byte
	FileHead  uuid.UUID
	FileTail  uuid.UUID
	ShareWith []byte //decrypt this with owner's sourceKey + filename
	ListB     map[string]uuid.UUID
}

type FileContent struct {
	EncContent  []byte
	HMACContent []byte
	NextUUID    uuid.UUID
	HMACnext    []byte
}

type Invite struct {
	Sharer_username  string
	File_struct_uuid uuid.UUID
	KeyA             []byte //enc with rsa
	File_key_uuid    uuid.UUID
}

type MetaData struct {
	Username       string
	FileStructUUID uuid.UUID
	KeyA           []byte //use this to decrypt file_key
}

/**
 * StoreFile stores a file for the user. If the file does not exist, it creates a new file with the provided content.
 * If the file already exists, it overwrites the old content with the new content.
 *
 * @param filename The name of the file to be stored.
 * @param content The content of the file to be stored.
 * @return An error if any operation fails, otherwise nil.
 */
func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// store the file
	file_uuid := usernameToUUID(userdata.Username, filename)
	meta_key := createKeys(userdata.SourceKey, filename)

	// check if the file existed
	_, ok := userlib.DatastoreGet(file_uuid)
	// create file for the first time
	if !ok {
		file_key := createFileKey()
		file_struct_uuid := uuid.New()
		keyA := createKeyA()

		// create meta_data
		meta_data, err := createMetaData(keyA, file_struct_uuid, userdata.Username)
		if err != nil {
			return err
		}
		// save the meta_data
		err = saveMetaData(file_uuid, meta_data, meta_key)
		if err != nil {
			return err
		}

		file_struct, err := createFileStruct(userdata, meta_key)
		if err != nil {
			return err
		}

		// save the content
		err = saveContent(file_struct, content, file_key)
		if err != nil {
			return err
		}

		// save file_key
		err = save_file_key(file_key, keyA, userdata.Username, file_struct, meta_key)
		if err != nil {
			return err
		}

		// saveFileStruct last when operation is complete
		err = saveFileStruct(file_struct, file_struct_uuid)
		if err != nil {
			return err
		}

	} else { // overwrite the old content

		// get the meta_data
		meta_data, err := getMetaData(file_uuid, meta_key)
		if err != nil {
			return err
		}

		// get the file_struct
		file_struct, err := getFileStruct(meta_data.FileStructUUID)
		if err != nil {
			return err
		}

		// get file_key
		file_key, err := get_file_key(meta_data)
		if err != nil {
			return err
		}

		// detelete the old content
		err = deleteContent(file_struct, file_key)
		if err != nil {
			return err
		}

		// save new content
		err = saveContent(file_struct, content, file_key)
		if err != nil {
			return err
		}

		// save file_struct when the last operations is done
		err = saveFileStruct(file_struct, meta_data.FileStructUUID)
		if err != nil {
			return err
		}
	}

	return nil
}

/*
AppendToFile appends content to a file associated with the user.
It checks the existence of the file, retrieves metadata, file structure, and file key,
saves the new content, and updates the file structure after the operation.

Parameters:
  - filename: the name of the file to append content to
  - content: the content to append to the file

Returns:
  - error: an error if any operation fails, nil otherwise
*/
func (userdata *User) AppendToFile(filename string, content []byte) error {

	// important variables
	file_uuid := usernameToUUID(userdata.Username, filename)
	meta_key := createKeys(userdata.SourceKey, filename)

	// check file's existence
	_, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return errors.New("file does not exist error")
	}

	// get meta_data
	meta_data, err := getMetaData(file_uuid, meta_key)
	if err != nil {
		return err
	}

	// get file_struct
	file_struct, err := getFileStruct(meta_data.FileStructUUID)
	if err != nil {
		return err
	}

	// get file_key
	file_key, err := get_file_key(meta_data)
	if err != nil {
		return err
	}

	// save new content
	err = saveContent(file_struct, content, file_key)
	if err != nil {
		return err
	}

	// save file_struct when the last operations is done
	err = saveFileStruct(file_struct, meta_data.FileStructUUID)
	if err != nil {
		return err
	}

	return nil
}

/*
LoadFile retrieves the content of a file associated with the user.
It performs various checks to ensure the file exists, retrieves metadata and file structure,
decrypts the file content using the file key, and returns the content.

Parameters:
  - filename: the name of the file to load content from

Returns:
  - content: the content of the file
  - error: an error if any operation fails, nil otherwise
*/
func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	// important variables
	file_uuid := usernameToUUID(userdata.Username, filename)
	meta_key := createKeys(userdata.SourceKey, filename)

	_, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return nil, errors.New("file does not exist error")
	}

	// get the meta_data
	// this get the same result as call DataStoreGet but I will check for tampered meta_data
	// and return a meta data
	meta_data, err := getMetaData(file_uuid, meta_key)
	if err != nil {
		return nil, err
	}

	// get file_struct
	file_struct, err := getFileStruct(meta_data.FileStructUUID)
	if err != nil {
		return nil, err
	}

	// get file_key
	file_key, err := get_file_key(meta_data)
	if err != nil {
		return nil, err
	}

	// load the file_content
	content, err = loadContent(file_struct, file_key)
	if err != nil {
		return nil, err
	}

	return content, nil

}

/*
CreateInvitation generates an invitation for sharing a file with a recipient user.
It performs various checks and operations to ensure the file exists, validate recipient existence,
verify recipient access to the file, handle ownership scenarios, create and save the invitation,
and update file structures accordingly.

Parameters:
  - filename: the name of the file for which the invitation is created
  - recipientUsername: the username of the recipient user

Returns:
  - invitationPtr: the UUID of the generated invitation
  - error: an error if any operation fails, nil otherwise
*/
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {

	// important variables
	file_uuid := usernameToUUID(userdata.Username, filename)
	meta_key := createKeys(userdata.SourceKey, filename)

	// check if file exit
	_, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return uuid.Nil, errors.New("file does not exist error")
	}

	// get the meta_data
	// this get the same result as call DataStoreGet but I will check for tampered meta_data
	// and return a meta data
	meta_data, err := getMetaData(file_uuid, meta_key)
	if err != nil {
		return uuid.Nil, err
	}

	// get file_struct
	file_struct, err := getFileStruct(meta_data.FileStructUUID)
	if err != nil {
		return uuid.Nil, err
	}

	// get file_key
	file_key, err := get_file_key(meta_data)
	if err != nil {
		return uuid.Nil, err
	}

	// check if recipient exist
	recipient_struct_uuid := usernameToUUID(recipientUsername, "user-struct")
	_, ok = userlib.DatastoreGet(recipient_struct_uuid)
	if !ok {
		err = errors.New("recipient does not exist")
		return uuid.Nil, err
	}

	// check if the recipient had access to the file
	_, err = getListB(file_struct, recipientUsername)
	if err == nil {
		return uuid.Nil, errors.New("recipient already had access to the file")
	}

	// get recipient pub key
	recipient_pub_key, ok := userlib.KeystoreGet(recipientUsername + "/rsa-pub")
	if !ok {
		return uuid.Nil, errors.New("cannot find recipient pub key")
	}

	// check if the current user is the owner of the file
	owner_key, err := checkOwnerShip(userdata, meta_data, file_struct, filename)
	if err == nil { // owner case

		// create new keyA for the recipient
		recipient_key_A := createKeyA()

		// save keyA to shareWith, and when recipient accept the invite, they add
		// their username and uuid of enc key_file to listB
		err = updateShareWith(file_struct, recipientUsername, recipient_key_A, owner_key)
		if err != nil {
			return uuid.Nil, err
		}

		// save the file_key and put the uuid of file_key to invite
		file_key_uuid, err := save_file_key_recipient(file_key, recipient_key_A)
		if err != nil {
			return uuid.Nil, err
		}

		// create invite
		invite := createInvite(recipientUsername, meta_data.FileStructUUID, recipient_key_A, file_key_uuid)

		// save the invite
		invite_uuid, err := saveInvite(invite, recipient_pub_key, userdata.DSSignKey)
		if err != nil {
			return uuid.Nil, err
		}

		invitationPtr = invite_uuid

	} else { // non-owner case

		// they just copy the access they have and pass it to the recipient

		// create the invite
		file_key_uuid, err := getListB(file_struct, meta_data.Username)
		if err != nil {
			return uuid.Nil, err
		}

		invite := createInvite(meta_data.Username, meta_data.FileStructUUID, meta_data.KeyA, file_key_uuid)

		// save the invite
		invite_uuid, err := saveInvite(invite, recipient_pub_key, userdata.DSSignKey)
		if err != nil {
			return uuid.Nil, err
		}

		invitationPtr = invite_uuid

	}

	// save file struc here
	err = saveFileStruct(file_struct, meta_data.FileStructUUID)
	if err != nil {
		return uuid.Nil, err
	}

	return invitationPtr, nil
}

/*
AcceptInvitation accepts an invitation from a sender to access and share a file.
It performs various operations including checking file existence, retrieving metadata keys,
validating the invitation, creating metadata for the receiver, saving metadata to the datastore,
updating file structures, and deleting the used invitation.

Parameters:
  - senderUsername: the username of the sender who shared the file
  - invitationPtr: the UUID of the invitation to accept
  - filename: the name of the file being shared

Returns:
  - error: an error if any operation fails, nil otherwise
*/
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// important variables
	file_uuid := usernameToUUID(userdata.Username, filename)
	meta_key := createKeys(userdata.SourceKey, filename)

	// return err if filename has taken
	_, ok := userlib.DatastoreGet(file_uuid)
	if ok {
		return errors.New("file already exists error")
	}

	// get the invite from data store
	invite, err := getInvite(userdata, invitationPtr, senderUsername)
	if err != nil {
		return err
	}

	// create a meta_data for the receiver
	meta_data, err := createMetaData(invite.KeyA, invite.File_struct_uuid, invite.Sharer_username)
	if err != nil {
		return err
	}

	// save meta_data to the data store
	err = saveMetaData(file_uuid, meta_data, meta_key)
	if err != nil {
		return err
	}

	// get the file_struct
	file_struct, err := getFileStruct(meta_data.FileStructUUID)
	if err != nil {
		return err
	}

	// update listB with recipient's username's uuid of enc file_key
	err = addListB(file_struct, invite.Sharer_username, invite.File_key_uuid)
	if err != nil {
		return err
	}

	// save file_struct
	err = saveFileStruct(file_struct, meta_data.FileStructUUID)
	if err != nil {
		return err
	}

	// delete the accepted invite uuid so it cannot be misused
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

/*
AcceptInvitation accepts an invitation from a sender to access and share a file.
It performs various operations including checking file existence, retrieving metadata keys,
validating the invitation, creating metadata for the receiver, saving metadata to the datastore,
updating file structures, and deleting the used invitation.

Parameters:
  - senderUsername: the username of the sender who shared the file
  - invitationPtr: the UUID of the invitation to accept
  - filename: the name of the file being shared

Returns:
  - error: an error if any operation fails, nil otherwise
*/
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// important variables
	file_uuid := usernameToUUID(userdata.Username, filename)
	meta_key := createKeys(userdata.SourceKey, filename)

	if recipientUsername == userdata.Username {
		return errors.New("cannot revoke access to own file")
	}

	// check if the file name exist with the user's name space
	_, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return errors.New("file does not exist error")
	}

	// get the meta_data
	meta_data, err := getMetaData(file_uuid, meta_key)
	if err != nil {
		return err
	}

	// get the file_struct
	file_struct, err := getFileStruct(meta_data.FileStructUUID)
	if err != nil {
		return err
	}

	// check if the current user is the owner of the file
	owner_key, err := checkOwnerShip(userdata, meta_data, file_struct, filename)
	if err != nil { // owner case
		return err
	}

	// remove the recipient from the shareWith
	err = removeRecipientFromShareWith(file_struct, recipientUsername, owner_key)
	if err != nil {
		return err
	}

	// remove recipient from listB
	err = removeListB(file_struct, recipientUsername)
	if err != nil {
		return err
	}

	// create a new file_key
	new_file_key := createFileKey()
	cur_file_key, err := get_file_key(meta_data)
	if err != nil {
		return err
	}

	// re-encrypt the file_content with new key_file
	err = reEncryptContent(file_struct, cur_file_key, new_file_key)
	if err != nil {
		return err
	}

	// get share_with
	share_with, err := getShareWith(file_struct, owner_key)
	if err != nil {
		return err
	}

	// update the new key_file location for non-revoked people
	for username, keyA := range *share_with {

		// create new file_key location
		new_file_key_uuid, err := save_file_key_recipient(new_file_key, keyA)
		if err != nil {
			return nil
		}

		// update listB
		err = addListB(file_struct, username, new_file_key_uuid)
		if err != nil {
			return nil
		}
	}

	// save the file_struct
	err = saveFileStruct(file_struct, meta_data.FileStructUUID)
	if err != nil {
		return nil
	}

	return nil
}

// ....... Helper Functions .........//

/*
usernameToUUID converts a username to a UUID based on a specific purpose.
It hashes the combination of the username and purpose, extracts the first 16 bytes of the hash,
and converts it to a UUID. If any error occurs during the conversion process, it panics with an error message.

Parameters:
  - username: the username to convert to UUID
  - purpose: the specific purpose for which the UUID is generated

Returns:
  - uuid.UUID: the UUID generated from the username and purpose
*/
func usernameToUUID(username string, purpose string) uuid.UUID {

	hash := userlib.Hash([]byte(username + "/" + purpose))
	result, err := uuid.FromBytes(hash[:16])
	if err != nil {
		panic(errors.New("Error occurs when converting username to UUID: " + err.Error()))
	}
	return result
}

/*
createSourceKey generates a source key based on the provided username and password using Argon2 key derivation.

Parameters:
  - username: the username used as part of the key generation
  - password: the password used as part of the key generation

Returns:
  - []byte: the generated source key
*/
func createSourceKey(username string, password string) []byte {
	/**
	 * createSourceKey generates a source key based on the provided username and password using Argon2 key derivation.
	 *
	 * @param username The username used as part of the key generation.
	 * @param password The password used as part of the key generation.
	 * @return []byte The generated source key.
	 */

	result := userlib.Argon2Key([]byte(password), []byte(username), 16)
	return result
}

/**
 * createKeys derives a new key from the source key based on the specified purpose.
 *
 * Parameters:
 * - source_key: The original key used for derivation.
 * - purpose: A string indicating the purpose for deriving the new key.
 *
 * Returns:
 * - A 16-byte derived key.
 *
 * Throws:
 * - Panic if an error occurs during key derivation.
 */
func createKeys(source_key []byte, purpose string) []byte {
	derivedKey, err := userlib.HashKDF(source_key, []byte(purpose))
	if err != nil {
		panic(errors.New("Error occurs when deriving source key: " + err.Error()))
	}
	return derivedKey[:16]
}

// func symEncPassword(password string, argon2_password []byte) []byte {
// 	/**
// 	 * This function symmetrically encrypt argon2_password using the plain password as key
// 	 *
// 	 * Parameters:
// 	 * - password: The password to be encrypted.
// 	 * - argon2_password: The Argon2 hashed password used for encryption key derivation.
// 	 *
// 	 * Returns:
// 	 * - Encrypted password as a byte slice.
// 	 */
// 	result := userlib.SymEnc([]byte(password), userlib.RandomBytes(16), argon2_password)
// 	return result
// }

// func hmacPassword(password string, enc_argon2_password []byte) []byte {
// 	result, _ := userlib.HMACEval([]byte(password), enc_argon2_password)

// 	return result
// }

// **** Invite Functions ****/

/**
 * createInvite creates and returns a pointer to an Invite object with the provided details.
 *
 * Parameters:
 * - sharer_username: the username of the sharer creating the invite
 * - file_struct_uuid: the UUID of the file structure
 * - keyA: the key A associated with the invite
 * - file_key_uuid: the UUID of the file key
 *
 * Returns:
 * - invite_ptr: a pointer to the created Invite object
 */
func createInvite(sharer_username string, file_struct_uuid uuid.UUID, keyA []byte, file_key_uuid uuid.UUID) (invite_ptr *Invite) {
	var invite Invite
	invite.Sharer_username = sharer_username
	invite.File_struct_uuid = file_struct_uuid
	invite.KeyA = keyA
	invite.File_key_uuid = file_key_uuid

	return &invite
}

/**
 * getInvite retrieves and decrypts an invite for a user.
 *
 * Parameters:
 * - userdata: a pointer to the user's data
 * - invitation_uuid: the UUID of the invitation to retrieve
 * - sender_username: the username of the sender
 *
 * Returns:
 * - invite_ptr: a pointer to the decrypted invite
 * - err: an error if decryption or retrieval fails
 */
func getInvite(userdata *User, invitation_uuid uuid.UUID, sender_username string) (invite_ptr *Invite, err error) {

	// get the auth_byte from the datastore
	auth_byte, ok := userlib.DatastoreGet(invitation_uuid)
	if !ok {
		return nil, errors.New("load invite auth_byte from data store failed")
	}

	// get the sender verify key
	sender_vk, ok := userlib.KeystoreGet(sender_username + "/verify-key")
	if !ok {
		return nil, errors.New("sender verify key not found")
	}

	// decrypt invite
	invite_ptr, err = decryptInvite(auth_byte, userdata.PKEDecKey, sender_vk)
	if err != nil {
		return nil, err
	}

	return invite_ptr, nil
}

/**
 * saveInvite saves the encrypted invite to the data store.
 *
 * Parameters:
 * - invite_ptr: a pointer to the Invite struct to be saved
 * - recipient_pub_key: the public key for encryption
 * - sender_sign_key: the private key for signing
 *
 * Returns:
 * - invite_uuid: the UUID of the saved invite
 * - err: an error if encryption fails
 */
func saveInvite(invite_ptr *Invite, recipient_pub_key userlib.PKEEncKey, sender_sign_key userlib.DSSignKey) (invite_uuid uuid.UUID, err error) {

	// create random uuid
	invite_uuid = createRandomUUID()

	// enc the invite
	auth_byte, err := encryptInvite(invite_ptr, recipient_pub_key, sender_sign_key)
	if err != nil {
		return uuid.Nil, err
	}

	// save the invite to the data store
	userlib.DatastoreSet(invite_uuid, auth_byte)

	return invite_uuid, nil

}

/**
 * encryptInvite encrypts an invite using RSA encryption and digital signatures.
 *
 * Parameters:
 * - invite: Pointer to the invite struct containing invite details
 * - recipient_pub_key: Public key for encryption
 * - sharer_sign_key: Private key for digital signatures
 *
 * Returns:
 * - auth_byte: Encrypted authentication data
 * - err: Error, if any
 */
func encryptInvite(invite *Invite, recipient_pub_key userlib.PKEEncKey, sharer_sign_key userlib.DSSignKey) (auth_byte []byte, err error) {

	// create and rsa auth
	var auth RSAAuthentication

	// marshal sharer_username
	sharer_username_byte, err := json.Marshal(invite.Sharer_username)
	if err != nil {
		return nil, errors.New("marshal sharer_username failed: " + err.Error())
	}
	// enc sharer_username
	enc_sharer_username, err := userlib.PKEEnc(recipient_pub_key, sharer_username_byte)
	if err != nil {
		return nil, errors.New("encrypt sharer_username failed: " + err.Error())
	}
	// sign sharer_username
	sig_share_username, err := userlib.DSSign(sharer_sign_key, enc_sharer_username)
	if err != nil {
		return nil, errors.New("sign sharer_username failed: " + err.Error())
	}
	auth.Enc_sharer_username = enc_sharer_username
	auth.Sig_share_username = sig_share_username

	// marshal file_struct_uuid
	file_struct_uuid_byte, err := json.Marshal(invite.File_struct_uuid)
	if err != nil {
		return nil, errors.New("marshal file_struct_uuid failed: " + err.Error())
	}
	// enc file_struct_uuid
	enc_file_struct_uuid, err := userlib.PKEEnc(recipient_pub_key, file_struct_uuid_byte)
	if err != nil {
		return nil, errors.New("encrypt file_struct_uuid failed: " + err.Error())
	}
	// sign file_struct_uuid
	sig_file_struct_uuid, err := userlib.DSSign(sharer_sign_key, enc_file_struct_uuid)
	if err != nil {
		return nil, errors.New("sign file_struct_uuid failed: " + err.Error())
	}
	auth.Enc_file_struct_uuid = enc_file_struct_uuid
	auth.Sig_file_struct_uuid = sig_file_struct_uuid

	//enc keyA
	enc_keyA, err := userlib.PKEEnc(recipient_pub_key, invite.KeyA)
	if err != nil {
		return nil, errors.New("encrypt keyA failed: " + err.Error())
	}
	// sign keyA
	sig_keyA, err := userlib.DSSign(sharer_sign_key, enc_keyA)
	if err != nil {
		return nil, errors.New("sign keyA failed: " + err.Error())
	}
	auth.Enc_keyA = enc_keyA
	auth.Sig_keyA = sig_keyA

	// marshal file_key_uuid
	file_key_uuid_byte, err := json.Marshal(invite.File_key_uuid)
	if err != nil {
		return nil, errors.New("marshal file_key_uuid failed: " + err.Error())
	}
	// enc file_key_uuid
	enc_file_key_uuid, err := userlib.PKEEnc(recipient_pub_key, file_key_uuid_byte)
	if err != nil {
		return nil, errors.New("encrypt file_key_uuid failed: " + err.Error())
	}
	// sign file_key_uuid
	sig_file_key_uuid, err := userlib.DSSign(sharer_sign_key, enc_file_key_uuid)
	if err != nil {
		return nil, errors.New("sign file_key_uuid failed: " + err.Error())
	}
	auth.Enc_file_key_uuid = enc_file_key_uuid
	auth.Sig_file_key_uuid = sig_file_key_uuid

	// marshal auth
	auth_byte, err = json.Marshal(auth)
	if err != nil {
		return nil, errors.New("marshal auth failed: " + err.Error())
	}

	return auth_byte, nil
}

/**
 * decryptInvite decrypts an invite using the recipient's private key and the sender's verification key.
 *
 * Parameters:
 * - auth_byte: the authentication byte to be decrypted
 * - recipient_priv_key: the recipient's private key for decryption
 * - sender_verify_key: the sender's verification key for verification
 *
 * Returns:
 * - invite_ptr: a pointer to the decrypted Invite struct
 * - err: an error if any decryption or verification step fails
 */
func decryptInvite(auth_byte []byte, recipient_priv_key userlib.PKEDecKey, sender_verify_key userlib.DSVerifyKey) (invite_ptr *Invite, err error) {

	// unmarshal the auth
	var auth RSAAuthentication
	err = json.Unmarshal(auth_byte, &auth)
	if err != nil {
		return nil, errors.New("unmarshal invite's auth failed: " + err.Error())
	}

	var invite Invite

	// verify sharer_username
	err = userlib.DSVerify(sender_verify_key, auth.Enc_sharer_username, auth.Sig_share_username)
	if err != nil {
		return nil, errors.New("sharer_username is not valid" + err.Error())
	}
	// dec sharer_username
	sharer_username_byte, err := userlib.PKEDec(recipient_priv_key, auth.Enc_sharer_username)
	if err != nil {
		return nil, errors.New("decrypt sharer_username failed" + err.Error())
	}
	// unmarshal sharer_username
	var share_username string
	err = json.Unmarshal(sharer_username_byte, &share_username)
	if err != nil {
		return nil, errors.New("unmarshal sharer_username failed" + err.Error())
	}
	invite.Sharer_username = share_username

	// verify file_struct_uuid
	err = userlib.DSVerify(sender_verify_key, auth.Enc_file_struct_uuid, auth.Sig_file_struct_uuid)
	if err != nil {
		return nil, errors.New("verify file_struct_uuid failed: " + err.Error())
	}
	// dec file_struct_uuid
	file_struct_uuid_byte, err := userlib.PKEDec(recipient_priv_key, auth.Enc_file_struct_uuid)
	if err != nil {
		return nil, errors.New("decrypt file_struct_uuid failed" + err.Error())
	}
	// unmarshal file_struct_uuid
	var file_struct_uuid uuid.UUID
	err = json.Unmarshal(file_struct_uuid_byte, &file_struct_uuid)
	if err != nil {
		return nil, errors.New("unmarshal file_struct_uuid failed" + err.Error())
	}
	invite.File_struct_uuid = file_struct_uuid

	// verify keyA
	err = userlib.DSVerify(sender_verify_key, auth.Enc_keyA, auth.Sig_keyA)
	if err != nil {
		return nil, errors.New("verify keyA failed: " + err.Error())
	}
	// dec keyA
	keyA, err := userlib.PKEDec(recipient_priv_key, auth.Enc_keyA)
	if err != nil {
		return nil, errors.New("decrypt keyA failed" + err.Error())
	}
	invite.KeyA = keyA

	// verify file_key_uuid
	err = userlib.DSVerify(sender_verify_key, auth.Enc_file_key_uuid, auth.Sig_file_key_uuid)
	if err != nil {
		return nil, errors.New("verify file_key_uuid failed: " + err.Error())
	}
	// dec file_key_uuid
	file_key_uuid_byte, err := userlib.PKEDec(recipient_priv_key, auth.Enc_file_key_uuid)
	if err != nil {
		return nil, errors.New("decrypt file_key_uuid failed" + err.Error())
	}
	// unmarshal file_key_uuid
	var file_key_uuid uuid.UUID
	err = json.Unmarshal(file_key_uuid_byte, &file_key_uuid)
	if err != nil {
		return nil, errors.New("unmarshal file_key_uuid failed" + err.Error())
	}
	invite.File_key_uuid = file_key_uuid

	return &invite, nil

}

/**
 * saveContent saves the encrypted content to the datastore.
 *
 * Parameters:
 *   - file_struct: pointer to the FileStruct containing file information
 *   - content: byte slice of the content to be saved
 *   - file_key: byte slice of the key used for encryption
 *
 * Returns:
 *   - error: an error if encryption or datastore set operation fails, nil otherwise
 */
func saveContent(file_struct *FileStruct, content []byte, file_key []byte) (err error) {
	// new tail
	new_uuid := uuid.New()

	// enc the content
	content_byte, err := encryptContent(content, file_key, new_uuid)
	if err != nil {
		return err
	}

	// save it to the old tail
	userlib.DatastoreSet(file_struct.FileTail, content_byte)

	// set new tail
	file_struct.FileTail = new_uuid

	return nil
}

/**
 * loadContent loads the content of a file from the datastore using the provided file structure and file key.
 * It iterates through the file blocks, decrypts the content, and appends it to the total content.
 * If any error occurs during the process, it returns an error with a corresponding message.
 *
 * @param file_struct Pointer to the FileStruct containing file metadata
 * @param file_key    Key used to decrypt the file content
 * @return total_content The concatenated content of the file blocks
 * @return err           Error encountered during the loading process, if any
 */
func loadContent(file_struct *FileStruct, file_key []byte) (total_content []byte, err error) {

	curr_uuid := file_struct.FileHead
	for curr_uuid != file_struct.FileTail {
		content_byte, ok := userlib.DatastoreGet(curr_uuid)
		if !ok {
			return nil, errors.New("file does not exist error")
		}
		content, next_uuid, err := decryptContent(content_byte, file_key)
		if err != nil {
			return nil, errors.New("Unmarshal file content error: " + err.Error())
		}
		total_content = append(total_content, content...)
		curr_uuid = next_uuid
	}
	return total_content, nil

}

/*
Encrypts the given content using the provided file key and generates HMAC values for the content and the next UUID.
The encrypted content along with the HMAC values are stored in a structured format and returned as a byte slice.

Parameters:
- content: The content to be encrypted as a byte slice.
- file_key: The key used for symmetric encryption as a byte slice.
- nextUUID: The UUID for the next content as a UUID type.

Returns:
- A byte slice containing the structured encrypted content.
- An error if any encryption or HMAC evaluation fails.
*/
func encryptContent(content []byte, file_key []byte, nextUUID uuid.UUID) ([]byte, error) {

	var file_content FileContent

	// enc the content with file_key
	enc_content := userlib.SymEnc(file_key, userlib.RandomBytes(16), content)
	hmac_content, err := userlib.HMACEval(file_key, enc_content)
	if err != nil {
		return nil, errors.New("attempt to hmac file content failed: " + err.Error())
	}

	// hmac next_uuid
	hmac_next_uuid, err := userlib.HMACEval(file_key, nextUUID[:])
	if err != nil {
		return nil, errors.New("attemtp to hmac next uuid failed: " + err.Error())
	}

	file_content.EncContent = enc_content
	file_content.HMACContent = hmac_content
	file_content.NextUUID = nextUUID
	file_content.HMACnext = hmac_next_uuid

	// marshal file_content
	file_content_byte, err := json.Marshal(file_content)
	if err != nil {
		return nil, errors.New("marshal file_content failed: " + err.Error())
	}

	return file_content_byte, nil
}

/**
 * decryptContent decrypts the encrypted content using the provided file key.
 * It unmarshals the content_byte into a FileContent struct, verifies the content HMAC,
 * verifies the nextUUID HMAC, and then decrypts the content using SymDec.
 *
 * Parameters:
 * - content_byte: the byte slice containing the encrypted content
 * - file_key: the byte slice representing the key used for encryption
 *
 * Returns:
 * - []byte: the decrypted content
 * - uuid.UUID: the next UUID
 * - error: an error if any decryption or verification step fails
 */
func decryptContent(content_byte []byte, file_key []byte) ([]byte, uuid.UUID, error) {

	var file_content FileContent

	// unmarshal the content_byte
	err := json.Unmarshal(content_byte, &file_content)
	if err != nil {
		return nil, uuid.Nil, errors.New("unmarshal file_content failed" + err.Error())
	}

	// verify content hmac
	check_content_hmac, err := userlib.HMACEval(file_key, file_content.EncContent)
	if err != nil {
		return nil, uuid.Nil, errors.New("generate check_content_hmac failed: " + err.Error())
	}
	valid := userlib.HMACEqual(check_content_hmac, file_content.HMACContent)
	if !valid {
		return nil, uuid.Nil, errors.New("hmac of the content does not match")
	}

	// verify nextUUID
	check_next_uuid_hmac, err := userlib.HMACEval(file_key, file_content.NextUUID[:])
	if err != nil {
		return nil, uuid.Nil, errors.New("generated check_next_uuid_hmac failed: " + err.Error())
	}
	valid = userlib.HMACEqual(check_next_uuid_hmac, file_content.HMACnext)
	if !valid {
		return nil, uuid.Nil, errors.New("hmac of the next_uuid does not match")
	}

	// decrypt content
	content := userlib.SymDec(file_key, file_content.EncContent)

	return content, file_content.NextUUID, nil

}

/**
 * reEncryptContent re-encrypts the content of a file using a new file key.
 * It iterates through the file blocks, decrypts the content using the current file key,
 * and then encrypts the content using the new file key before storing it back in the data store.
 *
 * Parameters:
 *   - file_struct: pointer to the FileStruct containing file information
 *   - cur_file_key: current file key used for decryption
 *   - new_file_key: new file key used for encryption
 *
 * Returns:
 *   - error: an error if any operation fails during re-encryption
 */
func reEncryptContent(file_struct *FileStruct, cur_file_key []byte, new_file_key []byte) (err error) {

	// store the content at the old uuid but encrypt new_file_key
	cur_uuid := file_struct.FileHead

	for cur_uuid != file_struct.FileTail {

		// get the content byte from datastore
		content_byte, ok := userlib.DatastoreGet(cur_uuid)
		if !ok {
			return errors.New("load content_byte failed")
		}

		// decrypt content
		cur_content, next_uuid, err := decryptContent(content_byte, cur_file_key)
		if err != nil {
			return err
		}

		// encrypt content with new_file_key
		new_auth_byte, err := encryptContent(cur_content, new_file_key, next_uuid)
		if err != nil {
			return err
		}

		// save the new encrypt content to the data store
		userlib.DatastoreSet(cur_uuid, new_auth_byte)

		// update cur_uuid
		cur_uuid = next_uuid

	}

	return nil
}

/**
 * deleteContent deletes the content of a file stored in the datastore.
 * It iterates through the file content, decrypts each block using the provided file_key,
 * deletes the content block from the datastore, and updates the file structure accordingly.
 *
 * Parameters:
 *   - file_struct: a pointer to the FileStruct containing file information
 *   - file_key: the key used to decrypt the file content
 *
 * Returns:
 *   - error: an error if any operation fails during content deletion
 */
func deleteContent(file_struct *FileStruct, file_key []byte) (err error) {

	cur_uuid := file_struct.FileHead
	for cur_uuid != file_struct.FileTail {

		// get the content byte from datastore
		content_byte, ok := userlib.DatastoreGet(cur_uuid)
		if !ok {
			return errors.New("load content_byte failed")
		}

		// decrypt content
		_, next_uuid, err := decryptContent(content_byte, file_key)
		if err != nil {
			return err
		}

		// delete the content from datastore
		userlib.DatastoreDelete(cur_uuid)

		// update cur_uuid
		cur_uuid = next_uuid

	}

	// move the tail up to head
	file_struct.FileTail = file_struct.FileHead

	return nil

}

/**** FileStruct Functions ****/

/**
 * createFileStruct creates a new FileStruct object based on the provided user data and owner key.
 *
 * Parameters:
 * - userdata: a pointer to the User struct containing user data
 * - owner_key: a byte slice representing the owner's key
 *
 * Returns:
 * - file_struct_ptr: a pointer to the created FileStruct object
 * - err: an error, if any, encountered during the creation process
 */
func createFileStruct(userdata *User, owner_key []byte) (file_struct_ptr *FileStruct, err error) {
	var file_struct FileStruct

	// add owner
	file_struct.Owner = userdata.Username
	// sign onwer
	owner_sig, err := userlib.DSSign(userdata.DSSignKey, []byte(userdata.Username))
	if err != nil {
		return nil, errors.New("sign owner failed: " + err.Error())
	}
	file_struct.OwnerSig = owner_sig

	// make file locations
	file_struct.FileHead = uuid.New()
	file_struct.FileTail = file_struct.FileHead

	// make share_with
	share_with, err := createShareWith()
	if err != nil {
		return nil, err
	}
	// encrypt share_with
	auth_byte, err := encryptShareWith(share_with, owner_key)
	if err != nil {
		return nil, err
	}
	file_struct.ShareWith = auth_byte

	list_b := createListB()
	file_struct.ListB = *list_b

	return &file_struct, nil
}

/**
 * checkFileStruct verifies the owner of a file by checking the owner's signature.
 *
 * Parameters:
 * - file_struct: a pointer to the FileStruct containing file information
 *
 * Returns:
 * - error: an error if the owner's verify key is not found or the owner's signature is invalid
 */
func checkFileStruct(file_struct *FileStruct) (err error) {

	owner_vk, ok := userlib.KeystoreGet(file_struct.Owner + "/verify-key")
	if !ok {
		return errors.New("owner verify key not found")
	}

	// check if the owner signature is valid
	err = userlib.DSVerify(owner_vk, []byte(file_struct.Owner), file_struct.OwnerSig)
	if err != nil {
		return errors.New("owner signature is not valid" + err.Error())
	}

	return nil

}

/**
 * saveFileStruct saves the given FileStruct pointer to the datastore with the provided UUID.
 *
 * Parameters:
 *   - file_struct: Pointer to the FileStruct to be saved
 *   - file_struct_uuid: UUID for identifying the FileStruct in the datastore
 *
 * Returns:
 *   - error: An error if there was an issue while marshaling the file_struct or setting it in the datastore, otherwise nil
 */
func saveFileStruct(file_struct *FileStruct, file_struct_uuid uuid.UUID) (err error) {

	file_struct_byte, err := json.Marshal(*file_struct)
	if err != nil {
		return errors.New("marshal file_struct failed: " + err.Error())
	}

	userlib.DatastoreSet(file_struct_uuid, file_struct_byte)

	return nil

}

/**
 * getFileStruct retrieves a FileStruct pointer from the datastore based on the provided UUID.
 *
 * Parameters:
 *   - file_struct_uuid: The UUID of the FileStruct to retrieve
 *
 * Returns:
 *   - file_struct_ptr: A pointer to the retrieved FileStruct
 *   - err: An error if the retrieval or unmarshalling process fails
 */
func getFileStruct(file_struct_uuid uuid.UUID) (file_struct_ptr *FileStruct, err error) {

	file_struct_byte, ok := userlib.DatastoreGet(file_struct_uuid)
	if !ok {
		return nil, errors.New("file_struct does not exist error")
	}

	var file_struct FileStruct
	err = json.Unmarshal(file_struct_byte, &file_struct)
	if err != nil {
		return nil, errors.New("unmarshal file_struct failed: " + err.Error())
	}

	err = checkFileStruct(&file_struct)
	if err != nil {
		return nil, err
	}
	return &file_struct, nil
}

/**
 * ShareWith functions
 */

/**
 * createShareWith creates a new map to store users with whom a resource will be shared.
 *
 * Returns:
 * - share_with_ptr: a pointer to the map containing user IDs and their corresponding access rights.
 * - err: an error, if any.
 */
func createShareWith() (share_with_ptr *map[string][]byte, err error) {
	share_with := make(map[string][]byte)
	return &share_with, nil
}

/**
 * getShareWith decrypts the share_with field of a FileStruct using the owner's key.
 *
 * Parameters:
 * - file_struct: a pointer to the FileStruct containing the share_with field to decrypt
 * - owner_key: the key of the owner used for decryption
 *
 * Returns:
 * - share_with_ptr: a pointer to a map containing the decrypted share_with data
 * - err: an error if decryption fails, nil otherwise
 */
func getShareWith(file_struct *FileStruct, owner_key []byte) (share_with_ptr *map[string][]byte, err error) {

	// decrypt share_with
	auth_byte := file_struct.ShareWith
	share_with, err := decryptShareWith(auth_byte, owner_key)
	if err != nil {
		return nil, err
	}

	return share_with, nil

}

/**
 * getKeyA retrieves the keyA associated with a specific user for a given file.
 *
 * Parameters:
 * - file_struct: a pointer to the FileStruct containing information about the file
 * - owner_key: the key of the file owner
 * - username: the username of the user for whom keyA is being retrieved
 *
 * Returns:
 * - keyA: the keyA associated with the specified user
 * - err: an error if the operation fails, such as if keyA for the user is not found
 */
func getKeyA(file_struct *FileStruct, owner_key []byte, username string) (keyA []byte, err error) {
	share_with, err := getShareWith(file_struct, owner_key)
	if err != nil {
		return nil, err
	}

	keyA, ok := (*share_with)[username]
	if !ok {
		return nil, errors.New("get keyA for user failed")
	}
	return keyA, nil
}

/**
 * updateShareWith updates the sharing permissions for a specific user in the given file structure.
 * It decrypts the current sharing information, adds or updates the user's key, and then encrypts the updated sharing information.
 *
 * Parameters:
 *   - file_struct: a pointer to the FileStruct containing the file's sharing information
 *   - username: the username of the user to update sharing permissions for
 *   - keyA: the key to be shared with the user
 *   - owner_key: the key of the file owner for decryption and encryption
 *
 * Returns:
 *   - error: an error if any operation fails during the update process
 */
func updateShareWith(file_struct *FileStruct, username string, keyA []byte, owner_key []byte) (err error) {

	// decrypt share_with
	share_with, err := getShareWith(file_struct, owner_key)
	if err != nil {
		return err
	}

	// update share_with
	(*share_with)[username] = keyA

	// encrypt share_with
	auth_byte, err := encryptShareWith(share_with, owner_key)
	if err != nil {
		return err
	}

	file_struct.ShareWith = auth_byte
	return nil

}

/**
 * removeRecipientFromShareWith removes a recipient from the shareWith list of a file.
 * It takes a pointer to a FileStruct, the recipient's username, and the owner's key as input parameters.
 * It retrieves the shareWith list, checks if the recipient is in the list, removes the recipient if present,
 * encrypts the updated shareWith, and updates the file_struct with the encrypted shareWith.
 * Returns an error if any operation fails, including if the recipient is not in the shareWith list.
 */
func removeRecipientFromShareWith(file_struct *FileStruct, recipient_username string, owner_key []byte) (err error) {

	// get the shareWith
	share_with, err := getShareWith(file_struct, owner_key)
	if err != nil {
		return err
	}

	// check if the recipient is in the share_with
	_, ok := (*share_with)[recipient_username]
	if !ok {
		return errors.New("recipient is not in the share_with")
	}

	// remove the recipient from the shareWith
	delete(*share_with, recipient_username)

	// encrypt share_with
	auth_byte, err := encryptShareWith(share_with, owner_key)
	if err != nil {
		return err
	}

	// update file_struct
	file_struct.ShareWith = auth_byte

	return nil

}

// func update_share_with(share_with *map[string][]byte, owner_key []byte) error {
// }

/*
Encrypts the data to be shared with specific users using the owner's key.

Parameters:
- share_with: A map containing the data to be shared with each user.
- owner_key: The key of the owner encrypting the data.

Returns:
- auth_byte: The encrypted authentication data.
- err: An error if any operation fails.
*/
func encryptShareWith(share_with *map[string][]byte, owner_key []byte) (auth_byte []byte, err error) {

	// marshal share_with
	share_with_byte, err := json.Marshal(*share_with)
	if err != nil {
		return nil, errors.New("marshal share_with failed: " + err.Error())
	}

	// encrypt share_with with own_key
	share_with_enc := userlib.SymEnc(owner_key, userlib.RandomBytes(16), share_with_byte)
	hmac, err := userlib.HMACEval(owner_key, share_with_enc)
	if err != nil {
		return nil, errors.New("create hmac for share_with failed: " + err.Error())
	}

	// create auth for share_with
	var auth Authentication
	auth.EncData = share_with_enc
	auth.HMACData = hmac

	// marshal auth
	auth_byte, err = json.Marshal(auth)
	if err != nil {
		return nil, errors.New("marshal for share_with auth failed: " + err.Error())
	}

	return auth_byte, nil

}

/**
 * decryptShareWith decrypts the share_with data using the provided authentication and owner key.
 *
 * Parameters:
 * - auth_byte: byte slice containing the authentication data
 * - owner_key: byte slice representing the owner's key
 *
 * Returns:
 * - share_with_ptr: pointer to a map containing decrypted share_with data
 * - err: error encountered during decryption process, if any
 */
func decryptShareWith(auth_byte []byte, owner_key []byte) (share_with_ptr *map[string][]byte, err error) {
	// unmarshal the auth
	var auth Authentication
	err = json.Unmarshal(auth_byte, &auth)
	if err != nil {
		return nil, errors.New("unmarshal share_with's auth failed: " + err.Error())
	}

	// verify hmac
	check_hmac, err := userlib.HMACEval(owner_key, auth.EncData)
	if err != nil {
		return nil, errors.New("generated check_hmac for share_with failed: " + err.Error())
	}
	valid := userlib.HMACEqual(check_hmac, auth.HMACData)
	if !valid {
		return nil, errors.New("share_with hmac does not match")
	}

	// decrypt for share_with
	share_with_byte := userlib.SymDec(owner_key, auth.EncData)

	// unmarshal for share_with
	var share_with map[string][]byte
	err = json.Unmarshal(share_with_byte, &share_with)
	if err != nil {
		return nil, errors.New("unmarshal share_with failed: " + err.Error())
	}

	return &share_with, nil

}

/**
 * MetaData functions
 */

/**
 * createMetaData creates a new MetaData object with the provided key, file UUID, and username.
 *
 * Parameters:
 *   - keyA: A byte slice representing the key.
 *   - file_struct_uuid: The UUID of the file structure.
 *   - username: The username associated with the MetaData.
 *
 * Returns:
 *   - meta_data_ptr: A pointer to the newly created MetaData object.
 *   - err: An error, if any.
 */
func createMetaData(keyA []byte, file_struct_uuid uuid.UUID, username string) (meta_data_ptr *MetaData, err error) {
	var meta_data MetaData
	meta_data.FileStructUUID = file_struct_uuid
	meta_data.KeyA = keyA
	meta_data.Username = username

	return &meta_data, nil
}

/*
*
SaveMetaData saves the metadata with the given UUID using encryption with the owner's key.

Parameters:
- meta_data_uuid: The UUID of the metadata to be saved.
- meta_data: A pointer to the MetaData struct to be encrypted and saved.
- owner_key: The key used for encryption.

Returns:
- An error if encryption or saving fails, nil otherwise.
*/
func saveMetaData(meta_data_uuid uuid.UUID, meta_data *MetaData, owner_key []byte) (err error) {
	// ownerkey = sourcekey + filename

	// encrypt meta_data
	auth_byte, err := encryptMetaData(meta_data, owner_key)
	if err != nil {
		return err
	}

	// save the meta_data
	userlib.DatastoreSet(meta_data_uuid, auth_byte)
	return nil

}

/**
 * getMetaData retrieves and decrypts the metadata associated with the given meta_data_uuid and owner_key.
 *
 * Parameters:
 * - meta_data_uuid: The UUID of the metadata to retrieve.
 * - owner_key: The key used to decrypt the metadata.
 *
 * Returns:
 * - meta_data_ptr: A pointer to the decrypted metadata.
 * - err: An error if decryption or retrieval fails.
 */
func getMetaData(meta_data_uuid uuid.UUID, owner_key []byte) (meta_data_ptr *MetaData, err error) {
	// ownerkey = sourcekey + filename

	// get the auth_byte of meta_data
	auth_byte, ok := userlib.DatastoreGet(meta_data_uuid)
	if !ok {
		return nil, errors.New("get meta_data_auth_byte failed")
	}

	// decrypt meta_data
	meta_data_ptr, err = decryptMetaData(auth_byte, owner_key)
	if err != nil {
		return nil, err
	}

	return meta_data_ptr, nil

}

/**
 * encryptMetaData encrypts the metadata using the provided owner key.
 *
 * Parameters:
 * - meta_data: a pointer to the MetaData struct containing the metadata to be encrypted
 * - owner_key: a byte slice representing the key used for encryption
 *
 * Returns:
 * - auth_byte: a byte slice containing the encrypted metadata along with HMAC authentication
 * - err: an error if any operation fails during encryption
 */
func encryptMetaData(meta_data *MetaData, owner_key []byte) (auth_byte []byte, err error) {
	// ownerkey = sourcekey + filename

	// marshal meta_data
	meta_data_byte, err := json.Marshal(meta_data)
	if err != nil {
		return nil, errors.New("marshal meta_data failed: " + err.Error())
	}

	// encrypt meta_data with owner_key
	meta_data_enc := userlib.SymEnc(owner_key, userlib.RandomBytes(16), meta_data_byte)
	hmac, err := userlib.HMACEval(owner_key, meta_data_enc)
	if err != nil {
		return nil, errors.New("create hmac for meta_data failed: " + err.Error())
	}

	// create auth for meta_data
	var auth Authentication
	auth.EncData = meta_data_enc
	auth.HMACData = hmac

	// marshal auth
	auth_byte, err = json.Marshal(auth)
	if err != nil {
		return nil, errors.New("marshal for meta_data auth failed: " + err.Error())
	}

	return auth_byte, nil
}

/**
 * decryptMetaData decrypts the metadata using the provided authentication bytes and owner key.
 *
 * Parameters:
 * - auth_byte: The authentication bytes used for decryption
 * - owner_key: The key of the owner for decryption
 *
 * Returns:
 * - meta_data_ptr: A pointer to the decrypted MetaData
 * - err: An error if decryption or unmarshalling fails
 */
func decryptMetaData(auth_byte []byte, owner_key []byte) (meta_data_ptr *MetaData, err error) {
	// ownerkey = sourcekey + filename

	// unmarshal the auth
	var auth Authentication
	err = json.Unmarshal(auth_byte, &auth)
	if err != nil {
		return nil, errors.New("unmarshal meta_data's auth failed: " + err.Error())
	}

	// verify hmac
	check_hmac, err := userlib.HMACEval(owner_key, auth.EncData)
	if err != nil {
		return nil, errors.New("generated check_hmac for meta_data failed: " + err.Error())
	}
	valid := userlib.HMACEqual(check_hmac, auth.HMACData)
	if !valid {
		return nil, errors.New("meta_data hmac does not match")
	}

	// decrypt for meta_data
	meta_data_byte := userlib.SymDec(owner_key, auth.EncData)

	// unmarshal for meta_data
	var meta_data MetaData
	err = json.Unmarshal(meta_data_byte, &meta_data)
	if err != nil {
		return nil, errors.New("unmarshal meta_data failed: " + err.Error())
	}

	return &meta_data, nil
}

// func shareMetaData() {    ... }    // ... more code here

/** file_key functions
 */

/**
 * createFileKey generates a random 16-byte file key using the userlib package.
 *
 * @return []byte: The randomly generated file key.
 */
func createFileKey() []byte {
	file_key := userlib.RandomBytes(16)
	return file_key
}

/**
 * save_file_key saves the file key to the datastore along with necessary updates.
 *
 * Parameters:
 * - file_key: The file key to be saved.
 * - keyA: The key used for encryption.
 * - username: The username associated with the file.
 * - file_struct: Pointer to the FileStruct containing file information.
 * - onwer_key: The owner's key for authorization.
 *
 * Returns:
 * - error: An error if any operation fails, nil otherwise.
 */
func save_file_key(file_key []byte, keyA []byte, username string, file_struct *FileStruct, onwer_key []byte) (err error) {

	file_key_uuid := uuid.New()

	// save file_key to the datastore
	auth_byte, err := encryptFileKey(file_key, keyA)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_key_uuid, auth_byte)

	// update listB
	err = addListB(file_struct, username, file_key_uuid)
	if err != nil {
		return err
	}

	// update share_with
	err = updateShareWith(file_struct, username, keyA, onwer_key)
	if err != nil {
		return err
	}

	return nil
}

/**
 * save_file_key_recipient saves the file key to the datastore after encrypting it with keyA.
 *
 * Parameters:
 * - file_key: The file key to be saved.
 * - keyA: The key used for encryption.
 *
 * Returns:
 * - file_key_uuid: The UUID of the saved file key.
 * - err: An error if encryption or datastore set operation fails.
 */
func save_file_key_recipient(file_key []byte, keyA []byte) (file_key_uuid uuid.UUID, err error) {

	file_key_uuid = createRandomUUID()

	// save file_key to the datastore
	auth_byte, err := encryptFileKey(file_key, keyA)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(file_key_uuid, auth_byte)

	return file_key_uuid, nil

}

/**
 * get_file_key retrieves the file key for a given file based on the provided metadata.
 *
 * Parameters:
 * - meta_data: a pointer to MetaData struct containing information about the file
 *
 * Returns:
 * - file_key: the file key as a byte slice
 * - err: an error if any operation fails during the retrieval process
 */
func get_file_key(meta_data *MetaData) (file_key []byte, err error) {

	// get the file struct
	file_struct, err := getFileStruct(meta_data.FileStructUUID)
	if err != nil {
		return nil, err
	}

	// get file_key_uuid
	file_key_uuid, err := getListB(file_struct, meta_data.Username)
	if err != nil {
		return nil, err
	}

	// get the file_key
	auth_byte, ok := userlib.DatastoreGet(file_key_uuid)
	if !ok {
		return nil, errors.New("load file_key auth failed")
	}
	file_key, err = decryptFileKey(auth_byte, meta_data.KeyA)
	if err != nil {
		return nil, err
	}

	return file_key, nil

}

/*
*
Encrypts a file key using a specified key and returns the encrypted file key along with an error, if any.

Parameters:
- file_key: The file key to be encrypted.
- keyA: The key used for encryption.

Returns:
- Encrypted file key along with an error, if any.
*/
func encryptFileKey(file_key []byte, keyA []byte) (file_key_enc []byte, err error) {

	// enc file_key with keyA
	enc_file_key := userlib.SymEnc(keyA, userlib.RandomBytes(16), file_key)
	hmac_file_key, err := userlib.HMACEval(keyA, enc_file_key)
	if err != nil {
		return nil, errors.New("create hmac for file_key failed: " + err.Error())
	}

	// create an auth for file key
	var auth Authentication
	auth.EncData = enc_file_key
	auth.HMACData = hmac_file_key

	// marshal auth
	auth_byte, err := json.Marshal(auth)
	if err != nil {
		return nil, errors.New("marshal for file_key auth failed: " + err.Error())
	}

	return auth_byte, nil

}

/**
 * decryptFileKey decrypts the file key using the provided authentication bytes and keyA.
 *
 * Parameters:
 * - auth_byte: The authentication bytes used to unmarshal the auth structure.
 * - keyA: The key used for HMAC evaluation and decryption.
 *
 * Returns:
 * - file_key: The decrypted file key.
 * - err: An error if any operation fails during decryption.
 */
func decryptFileKey(auth_byte []byte, keyA []byte) (file_key []byte, err error) {

	// unmarshal the auth
	var auth Authentication
	err = json.Unmarshal(auth_byte, &auth)
	if err != nil {
		return nil, errors.New("unmarshal file_stuct's auth failed: " + err.Error())
	}

	// check hmac
	check_hmac, err := userlib.HMACEval(keyA, auth.EncData)
	if err != nil {
		return nil, errors.New("generated check_hmac for file_key failed: " + err.Error())
	}
	valid := userlib.HMACEqual(check_hmac, auth.HMACData)
	if !valid {
		return nil, errors.New("file_key hmac does not match")
	}

	// decrypt for file_key
	file_key = userlib.SymDec(keyA, auth.EncData) // enc file_key with keyA

	return file_key, nil
}

/**** ListB Functions ****/

/**
 * createListB creates a new empty map of strings to UUIDs and returns a pointer to it.
 *
 * @return A pointer to the newly created map[string]uuid.UUID.
 */
func createListB() (listB_ptr *map[string]uuid.UUID) {
	listB := make(map[string]uuid.UUID)
	return &listB
}

/**
 * addListB adds a file key UUID to the ListB map in the given FileStruct for the specified username.
 *
 * Parameters:
 *   - file_struct: a pointer to the FileStruct where the file key UUID will be added
 *   - username: the username associated with the file key UUID
 *   - file_key_uuid: the UUID of the file key to be added
 *
 * Returns:
 *   - err: an error if the ListB map is nil
 */
func addListB(file_struct *FileStruct, username string, file_key_uuid uuid.UUID) (err error) {
	if file_struct.ListB == nil {
		return errors.New("ListB is nil")
	}
	file_struct.ListB[username] = file_key_uuid
	return nil
}

/**
 * removeListB removes the specified username from the listB of the given FileStruct.
 *
 * Parameters:
 *   - file_struct: a pointer to the FileStruct containing the listB
 *   - username: the username to be removed from listB
 *
 * Returns:
 *   - error: an error if the username is not in listB or if listB is nil, nil otherwise
 */
func removeListB(file_struct *FileStruct, username string) (err error) { // remove the key from listB
	if file_struct.ListB == nil {
		return errors.New("ListB is nil")
	}

	// check if the person is in listB
	_, ok := file_struct.ListB[username]
	if !ok {
		return errors.New("user is not in listB")
	}

	delete(file_struct.ListB, username)
	return nil
}

/**
 * getListB retrieves the file key UUID associated with a specific username from the given FileStruct.
 *
 * Parameters:
 *   - file_struct: a pointer to the FileStruct containing the mapping of usernames to file key UUIDs
 *   - username: the username for which the file key UUID needs to be retrieved
 *
 * Returns:
 *   - file_key_uuid: the UUID of the file key associated with the provided username
 *   - err: an error if the username is not found in the mapping or if the ListB is nil
 */
func getListB(file_struct *FileStruct, username string) (file_key_uuid uuid.UUID, err error) {
	if file_struct.ListB == nil {
		return uuid.Nil, errors.New("ListB is nil")
	}

	file_key_uuid, ok := file_struct.ListB[username]
	if !ok {
		return uuid.Nil, errors.New("get file_key location for this user failed")
	}

	return file_key_uuid, nil
}

/*** KeyA Functions ****/

/**
 * createKeyA generates a random 16-byte key using the userlib package.
 *
 * @return []byte: A randomly generated 16-byte key.
 */
func createKeyA() []byte {
	keyA := userlib.RandomBytes(16)
	return keyA
}

/**** Ownership functions ****/

/**
 * checkOwnerShip checks if the user is the owner of the file based on the provided user data, metadata, file structure, and file name.
 * Returns the owner key if the user is the owner, otherwise returns an error.
 */
func checkOwnerShip(userdata *User, meta_data *MetaData, file_truct *FileStruct, file_name string) (owner_key []byte, err error) {
	valid := (userdata.Username == meta_data.Username)
	if !valid {
		return nil, errors.New("not the file owner")
	}

	err = checkFileStruct(file_truct)
	if err != nil {
		return nil, err
	}

	valid = (meta_data.Username == file_truct.Owner)
	if !valid {
		return nil, errors.New("not the file owner")
	}

	owner_key = createKeys(userdata.SourceKey, file_name)
	if err != nil {
		return nil, err
	}

	return owner_key, nil

}

/**
 * createRandomUUID generates a new random UUID.
 *
 * @return uuid.UUID - A randomly generated UUID.
 */
func createRandomUUID() uuid.UUID {
	return uuid.New()
}

func marshal_sign_key(sign_key userlib.DSSignKey) ([]byte, error) {
	// marshal the sign key
	sign_key_byte, err := json.Marshal(sign_key)
	if err != nil {
		return nil, errors.New("marshal sign key failed: " + err.Error())
	}
	return sign_key_byte, nil
}

func measureBandwith(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}
