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
	Owner           string
	HmacOwner       []byte
	FileStruct_uuid uuid.UUID
	Hmac_UUID       []byte
	EncFileKey      []byte //enc with rsa
	Signature       []byte
}

type MetaData struct {
	Username       string
	FileStructUUID uuid.UUID
	KeyA           []byte //use this to decrypt file_key
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// // store the file
	// file_uuid := usernameToUUID(userdata.Username, "/"+filename)
	// meta_key := createKeys(userdata.SourceKey, filename)

	// // check if the file existed
	// _, ok := userlib.DatastoreGet(file_uuid)
	// if !ok {
	// 	// create new file struct
	// 	file_key := userlib.RandomBytes(16)
	// 	file_struct_uuid := userlib.RandomBytes(16)

	// 	file_struct, err := createNewFileStruct(userdata, filename)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	// save the content
	// 	err = saveContent(file_struct, content, _)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	// save the file struct
	// 	file_struct_byte, err := json.Marshal(file_struct)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	userlib.DatastoreSet(file_uuid, file_struct_byte)
	// }

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// file_uuid := usernameToUUID(userdata.Username, "/"+filename)
	// // meta_key := createKeys(userdata.SourceKey, filename)
	// _ = []byte("")

	// // get the file struct
	// file_struct_byte, ok := userlib.DatastoreGet(file_uuid)
	// if !ok {
	// 	return errors.New("File does not exist error")
	// }
	// var file_struct FileStruct
	// err := json.Unmarshal(file_struct_byte, &file_struct)
	// if err != nil {
	// 	return errors.New("Unmarshal file struct error: " + err.Error())
	// }

	// // append the content
	// err = saveContent(&file_struct, content, _)
	// if err != nil {
	// 	return err
	// }

	// // save the file struct
	// file_struct_byte, err = json.Marshal(file_struct)
	// if err != nil {
	// 	return err
	// }
	// userlib.DatastoreSet(file_uuid, file_struct_byte)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	// file_uuid := usernameToUUID(userdata.Username, "/"+filename)
	// // meta_key := createKeys(userdata.SourceKey, filename)

	// // get the file struct
	// file_struct_byte, ok := userlib.DatastoreGet(file_uuid)
	// if !ok {
	// 	return nil, errors.New("File does not exist error")
	// }
	// var file_struct FileStruct
	// err = json.Unmarshal(file_struct_byte, &file_struct)
	// if err != nil {
	// 	return nil, errors.New("Unmarshal file struct error: " + err.Error())
	// }

	// //load the content
	// content, err = loadContent(&file_struct, _)
	// if err != nil {
	// 	return nil, err
	// }

	//

	return content, nil

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

func loadContent(file_struct *FileStruct, file_key []byte) (total_content []byte, err error) {

	curr_uuid := file_struct.FileHead
	for curr_uuid != file_struct.FileTail {
		content_byte, ok := userlib.DatastoreGet(curr_uuid)
		if !ok {
			return nil, errors.New("File does not exist error")
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

/**** FileStruct Functions ****/

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

func saveFileStruct(file_struct *FileStruct, file_struct_uuid uuid.UUID) (err error) {

	file_struct_byte, err := json.Marshal(*file_struct)
	if err != nil {
		return errors.New("marshal file_struct failed: " + err.Error())
	}

	userlib.DatastoreSet(file_struct_uuid, file_struct_byte)

	return nil

}

func loadFileStruct(file_struct_uuid uuid.UUID) (file_struct_ptr *FileStruct, err error) {

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

func createShareWith() (share_with_ptr *map[string][]byte, err error) {
	share_with := make(map[string][]byte)
	return &share_with, nil
}

func getShareWith(file_struct *FileStruct, owner_key []byte) (share_with_ptr *map[string][]byte, err error) {

	// decrypt share_with
	auth_byte := file_struct.ShareWith
	share_with, err := decryptShareWith(auth_byte, owner_key)
	if err != nil {
		return nil, err
	}

	return share_with, nil

}

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

// func update_share_with(share_with *map[string][]byte, owner_key []byte) error {
// }

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
		return nil, errors.New("share_with hmac does not match" + err.Error())
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
func createMetaData(keyA []byte, file_struct_uuid uuid.UUID, username string) (meta_data_ptr *MetaData, err error) {
	var meta_data MetaData
	meta_data.FileStructUUID = file_struct_uuid
	meta_data.KeyA = keyA
	meta_data.Username = username

	return &meta_data, nil
}

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
		return nil, errors.New("meta_data hmac does not match" + err.Error())
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
func createFileKey() []byte {
	file_key := userlib.RandomBytes(16)
	return file_key
}

func save_file_key(file_key []byte, file_key_uuid uuid.UUID, keyA []byte, username string, file_struct *FileStruct) (err error) {
	// enc file_key with keyA
	// auth_byte, err := encryptFileKey(file_key, keyA)
	// if err != nil {
	// 	return err
	// }

	// // save the file key
	// userlib.DatastoreSet(file_key_uuid, auth_byte)

	// // update share_with
	// err = updateShareWith(file_struct, username, keyA)
	return nil
}

func get_file_key(fileKey_uuid uuid.UUID, keyA []byte) (file_key []byte, err error) {

	// get the auth_byte of file key
	auth_byte, ok := userlib.DatastoreGet(fileKey_uuid)
	if !ok {
		return nil, errors.New("File_key does not exist error")
	}

	// decrypt the auth_byte for file_key
	file_key, err = decryptFileKey(auth_byte, keyA)
	if err != nil {
		return nil, err
	}

	return file_key, nil
}

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

	return auth_byte, nil

}

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
		return nil, errors.New("file_key hmac does not match" + err.Error())
	}

	// decrypt for file_key
	file_key = userlib.SymDec(keyA, auth.EncData) // enc file_key with keyA

	return file_key, nil
}

/**** ListB Functions ****/

func createListB() (listB_ptr *map[string]uuid.UUID) {
	listB := make(map[string]uuid.UUID)
	return &listB
}

func addListB(file_struct *FileStruct, username string, file_key_uuid uuid.UUID) (err error) {
	if file_struct.ListB == nil {
		return errors.New("ListB is nil")
	}
	file_struct.ListB[username] = file_key_uuid
	return nil
}

func removeListB(file_struct *FileStruct, username string) (err error) { // remove the key from listB
	if file_struct.ListB == nil {
		return errors.New("ListB is nil")
	}
	delete(file_struct.ListB, username)
	return nil
}

func getListB(file_struct *FileStruct, username string) (file_key_uuid uuid.UUID, err error) {
	if file_struct.ListB == nil {
		return uuid.Nil, errors.New("ListB is nil")
	}

	file_key_uuid, ok := file_struct.ListB[username]
	if !ok {
		return uuid.Nil, errors.New(fmt.Sprintf("user %s does not have a file key", username))
	}

	return file_key_uuid, nil
}

/*** KeyA Functions ****/
func createKeyA() []byte {
	keyA := userlib.RandomBytes(16)
	return keyA
}

func createRandomUUID() uuid.UUID {
	return uuid.New()
}
