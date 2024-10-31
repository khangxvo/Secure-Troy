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
	SignPerson string
	RSAEncData []byte
	SignData   []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check for empty username error
	if username == "" {
		err = errors.New("username cannot be empty error")
		return nil, err
	}

	// check for username existed error
	user_struct_uuid := usernameToUUID(username, "/user-struct")
	_, ok := userlib.DatastoreGet(user_struct_uuid)
	if ok {
		err = errors.New("user existed error")
		return nil, err
	}

	username_password_uuid := usernameToUUID(username, "/password")
	_, ok = userlib.DatastoreGet(username_password_uuid)
	if ok {
		err = errors.New("user existed error")
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
	userlib.KeystoreSet(username+"/verify-key", ds_verify_key)

	// RSA Key
	rsa_pub_key, rsa_priv_key, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("RSAKey generation error: " + err.Error())
	}
	userlib.KeystoreSet(username+"/rsa-pub", rsa_pub_key)

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

func GetUser(username string, password string) (userdataptr *User, err error) {
	// check if username exist
	user_struct_uuid := usernameToUUID(username, "/user-struct")
	marshal_user_struct_auth, ok := userlib.DatastoreGet(user_struct_uuid)
	if !ok {
		return nil, errors.New("User does not exist error")
	}

	// check if the authetnication is correct
	username_password_uuid := usernameToUUID(username, "/password")
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
		return nil, errors.New("Invalid username or password")
	}

	// check for tampered data
	hmac_argon2_key := createKeys(source_key, "hmac-argon2-key")
	hmac_argon2_password, err := userlib.HMACEval(hmac_argon2_key, username_password_auth.EncData)
	if err != nil {
		return nil, errors.New("HMAC generated error: " + err.Error())
	}
	auth_valid := userlib.HMACEqual(hmac_argon2_password, username_password_auth.HMACData)
	if !auth_valid {
		return nil, errors.New("Tampered user's authentication")
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
		return nil, errors.New("Tampered user struct authentication")
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
	HmacOwner []byte
	FileHead  uuid.UUID
	FileTail  uuid.UUID
	SymEncKey []byte
	Invites   map[string]uuid.UUID
}

type FileContent struct {
	EncContent  []byte
	HMACContent []byte
	NextUUID    uuid.UUID
	HMACnext    []byte
}

type Invite struct {
	Owner           string
	HmacOwner       []byte
	FileStruct_uuid uuid.UUID
	Hmac_UUID       []byte
	EncFileKey      []byte //enc with rsa
	Signature       []byte
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	file_uuid := usernameToUUID(userdata.Username, "/"+filename)

	file_byte, ok := userlib.DatastoreGet(file_uuid)

	// create file for the first time
	if !ok {
		file_key := userlib.RandomBytes(16)

		// create new file struct
		file_struct, err := createNewFileStruct(userdata.Username, file_key)
		if err != nil {
			return err
		}

		// save the content
		err = saveContent(file_struct, content)
		if err != nil {
			return err
		}

	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	return nil, nil

}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

// ....... Helper Functions .........//

func usernameToUUID(username string, purpose string) uuid.UUID {
	/*
		usernameToUUID generates a UUID based on the provided `username` and `purpose`.
		It uses the `userlib.Hash` function to hash the concatenation of `username` and `purpose`,
		then converts the hash bytes to a UUID. If any error occurs during the conversion process,
		it panics with an error message.

		Parameters:
		- `username`: the username to be used in generating the UUID.
		- `purpose`: a string indicating the purpose for generating the UUID.

		Returns:
		- A UUID generated based on the `username` and `purpose`.
	*/

	hash := userlib.Hash([]byte(username + purpose))
	result, err := uuid.FromBytes(hash[:16])
	if err != nil {
		panic(errors.New("Error occurs when converting username to UUID: " + err.Error()))
	}
	return result
}

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

func createKeys(source_key []byte, purpose string) []byte {
	derivedKey, err := userlib.HashKDF(source_key, []byte(purpose))
	if err != nil {
		panic(errors.New("Error occurs when deriving source key: " + err.Error()))
	}
	return derivedKey[:16]
}

func symEncPassword(password string, argon2_password []byte) []byte {
	/**
	 * This function symmetrically encrypt argon2_password using the plain password as key
	 *
	 * Parameters:
	 * - password: The password to be encrypted.
	 * - argon2_password: The Argon2 hashed password used for encryption key derivation.
	 *
	 * Returns:
	 * - Encrypted password as a byte slice.
	 */
	result := userlib.SymEnc([]byte(password), userlib.RandomBytes(16), argon2_password)
	return result
}

func hmacPassword(password string, enc_argon2_password []byte) []byte {
	result, _ := userlib.HMACEval([]byte(password), enc_argon2_password)

	return result
}

func createNewFileStruct(username string, file_key []byte) (file_struct_ptr *FileStruct, err error) {
	var file_struct FileStruct

	file_struct.Owner = username
	file_struct.FileHead = uuid.New()
	file_struct.FileTail = file_struct.FileHead
	file_struct.SymEncKey = file_key

	return &file_struct, nil
}

func saveContent(file_struct *FileStruct, content []byte) (err error) {
	// new tail
	new_uuid := uuid.New()

	// enc the content
	content_byte, err := encryptContent(content, file_struct.SymEncKey, new_uuid)
	if err != nil {
		return err
	}

	// save it to the old tail
	userlib.DatastoreSet(file_struct.FileTail, content_byte)

	// set new tail
	file_struct.FileTail = new_uuid

	return nil
}

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
		return nil, uuid.Nil, errors.New("hmac of the content does not match: " + err.Error())
	}

	// verify nextUUID
	check_next_uuid_hmac, err := userlib.HMACEval(file_key, file_content.NextUUID[:])
	if err != nil {
		return nil, uuid.Nil, errors.New("generated check_next_uuid_hmac failed: " + err.Error())
	}
	valid = userlib.HMACEqual(check_next_uuid_hmac, file_content.HMACnext)
	if !valid {
		return nil, uuid.Nil, errors.New("hmac of the next_uuid does not match: " + err.Error())
	}

	// decrypt content
	content := userlib.SymDec(file_key, file_content.EncContent)

	return content, file_content.NextUUID, nil

}

func encryptFileStruct(file_struct *FileStruct, file_key []byte) (file_byte []byte, err error) {

	var auth Authentication

	// marshal file_struct
	marshal_file_struct, err := json.Marshal(file_struct)
	if err != nil {
		return nil, errors.New("marshal file_struct failed: " + err.Error())
	}

	// encrypt file_struct
	enc_file_struct := userlib.SymEnc(file_key, userlib.RandomBytes(16), marshal_file_struct)

	// hmac for file_struct
	hmac_file_struct, err := userlib.HMACEval(file_key, enc_file_struct)
	if err != nil {
		return nil, errors.New("create hmac for file_struct failed: " + err.Error())
	}

	auth.EncData = enc_file_struct
	auth.HMACData = hmac_file_struct

	// marshal auth
	auth_byte, err := json.Marshal(auth)
	if err != nil {
		return nil, errors.New("marshal for file_struct auth failed: " + err.Error())
	}

	return auth_byte, nil
}

func descryptFileStruct(auth_byte []byte, file_key []byte) (file_struct_ptr *FileStruct, err error) {

	// unmarshal the auth
	var auth Authentication
	err = json.Unmarshal(auth_byte, &auth)
	if err != nil {
		return nil, errors.New("unmarshal file_stuct's auth failed: " + err.Error())
	}

	// verify hmac
	check_hmac, err := userlib.HMACEval(file_key, auth.EncData)
	if err != nil {
		return nil, errors.New("generated check_hmac for file_struct failed: " + err.Error())
	}
	valid := userlib.HMACEqual(check_hmac, auth.HMACData)
	if !valid {
		return nil, errors.New("file_struct hmac does not match" + err.Error())
	}

	// decrypt for marshal of file_struct
	file_struct_byte := userlib.SymDec(file_key, auth.EncData)

	// unmarshal for file_struct
	var file_struct FileStruct
	err = json.Unmarshal(file_struct_byte, &file_struct)
	if err != nil {
		return nil, errors.New("unmarshal file_struct failed: " + err.Error())
	}

	return &file_struct, nil

}
