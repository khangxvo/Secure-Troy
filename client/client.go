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
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

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

func InitUser(username string, password string) (userdataptr *User, err error) {
	// // check for empty username error
	// if username == "" {
	// 	err = errors.New("username cannot be empty error")
	// 	return nil, err
	// }

	// // check for username existed error
	// user_struct_uuid := usernameToUUID(username, "/user-struct")
	// _, ok := userlib.DatastoreGet(user_struct_uuid)
	// if ok {
	// 	err = errors.New("user existed error")
	// 	return nil, err
	// }

	// /* ######## Creating new user ######## */

	// // Link username password
	// temp_uuid := usernameToUUID(username, "/password")
	// argon2_password := createSourceKey(username, password)
	// enc_argon2_password := userlib.SymEnc([]byte(password), userlib.RandomBytes(16), argon2_password)
	// hmac_argon2_password, err := userlib.HMACEval([]byte(password), enc_argon2_password)
	// if err != nil {
	// 	return nil, errors.New("hmac argon2 password error: " + err.Error())
	// }
	// // ask abt this
	// temp_arr := append(enc_argon2_password, hmac_argon2_password...)
	// fmt.Println(temp_uuid, temp_arr)
	// // userlib.DatastoreSet(temp_uuid)

	var userdata User
	userdata.Username = username
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
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

	/*
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
