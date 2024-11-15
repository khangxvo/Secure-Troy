package client

///////////////////////////////////////////////////
//                                               //
// Everything in this file will NOT be graded!!! //
//                                               //
///////////////////////////////////////////////////

// In this unit tests file, you can write white-box unit tests on your implementation.
// These are different from the black-box integration tests in client_test.go,
// because in this unit tests file, you can use details specific to your implementation.

// For example, in this unit tests file, you can access struct fields and helper methods
// that you defined, but in the integration tests (client_test.go), you can only access
// the 8 functions (StoreFile, LoadFile, etc.) that are common to all implementations.

// In this unit tests file, you can write InitUser where you would write client.InitUser in the
// integration tests (client_test.go). In other words, the "client." in front is no longer needed.

import (
	"testing"

	userlib "github.com/cs161-staff/project2-userlib"

	_ "encoding/hex"

	_ "errors"

	. "github.com/onsi/ginkgo/v2"

	. "github.com/onsi/gomega"

	_ "strconv"

	_ "strings"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Unit Tests")
}

const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const longMessage = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

var _ = Describe("Client Unit Tests", func() {
	default_password := "password"
	alice_username := "alice"
	bob_username := "bob"
	charlie_username := "charlie"
	file_key_A := []byte("keyA")
	file_key_B := []byte("keyB")
	alice_file := "fileA"
	bob_file := "fileB"
	charlie_file := "fileC"
	file_KeyA_uuid := createRandomUUID()
	// source_key_A := createSourceKey(alice_username, default_password)
	// source_key_B := createSourceKey(bob_username, default_password)
	keyAA := createKeyA()
	// file_KeyB_uuid := createRandomUUID()

	owner_key := userlib.RandomBytes(16)

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Unit Tests", func() {
		Specify("Basic Test: Check that the Username field is set for a new user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			// Note: In the integration tests (client_test.go) this would need to
			// be client.InitUser, but here (client_unittests.go) you can write InitUser.
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			// Note: You can access the Username field of the User struct here.
			// But in the integration tests (client_test.go), you cannot access
			// struct fields because not all implementations will have a username field.
			Expect(alice.Username).To(Equal("alice"))
		})
	})

	Describe("Test share_with function", func() {
		Specify("Test intialize share_with", func() {
			userlib.DebugMsg("Initilizing share_with")
			_, err := createShareWith()

			Expect(err).To(BeNil())
		})

		Specify("Test getShareWith", func() {
			file_struct := &FileStruct{}
			userlib.DebugMsg("Initilizing share_with")
			share_with, err := createShareWith()
			Expect(err).To(BeNil())

			userlib.DebugMsg("Assigning value to khang")
			(*share_with)["khang"] = []byte("value")

			userlib.DebugMsg("Encrypt share_with")
			auth_byte, err := encryptShareWith(share_with, owner_key)
			Expect(err).To(BeNil())

			(*file_struct).ShareWith = auth_byte

			userlib.DebugMsg("Calling getShareWith")
			share_with_copy, err := getShareWith(file_struct, owner_key)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking for result of getting khang")
			Expect((*share_with_copy)["khang"]).To(Equal((*share_with)["khang"]))
		})

		Specify("Test updateShareWith", func() {
			file_struct := &FileStruct{}
			owner_key := userlib.RandomBytes(16)

			userlib.DebugMsg("Initilizing share_with")
			share_with, err := createShareWith()
			Expect(err).To(BeNil())

			userlib.DebugMsg("Encrypt share_with")
			auth_byte, err := encryptShareWith(share_with, owner_key)
			Expect(err).To(BeNil())

			(*file_struct).ShareWith = auth_byte

			userlib.DebugMsg("Update share_with")
			err = updateShareWith(file_struct, alice_username, file_key_A, owner_key)
			Expect(err).To(BeNil())
			err = updateShareWith(file_struct, bob_username, file_key_B, owner_key)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling getShareWith")
			share_with_copy, err := getShareWith(file_struct, owner_key)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking for result of getting result")
			Expect((*share_with_copy)[alice_username]).To(Equal(file_key_A))
			Expect((*share_with_copy)[bob_username]).To(Equal(file_key_B))
		})

	})

	Describe("Test ListB functions", func() {
		Specify("Test update non-exist listB", func() {
			file_struct := &FileStruct{}

			err := addListB(file_struct, alice_username, file_KeyA_uuid)
			Expect(err).ToNot(BeNil())

			err = removeListB(file_struct, alice_username)
			Expect(err).ToNot(BeNil())
		})

		Specify("Test update exist listB", func() {
			file_struct := &FileStruct{}

			listB := createListB()
			file_struct.ListB = *listB

			err := addListB(file_struct, alice_username, file_KeyA_uuid)
			Expect(err).To(BeNil())

			file_key_uuid, err := getListB(file_struct, alice_username)
			Expect(err).To(BeNil())
			Expect(file_key_uuid).To(Equal(file_KeyA_uuid))

			err = removeListB(file_struct, alice_username)
			Expect(err).To(BeNil())
			_, err = getListB(file_struct, alice_username)
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Test MetaData Functions", func() {
		Specify("Test getMetaData", func() {
			file_struct_uuid := createRandomUUID()

			// create metadata
			meta_data_A, err := createMetaData(keyAA, file_struct_uuid, alice_username)
			Expect(err).To(BeNil())

			meta_data_A_uuid := createRandomUUID()
			err = saveMetaData(meta_data_A_uuid, meta_data_A, owner_key)
			Expect(err).To(BeNil())

			copy, err := getMetaData(meta_data_A_uuid, owner_key)
			Expect(err).To(BeNil())

			// check for result of getting meta_data_A
			userlib.DebugMsg("expect keyA is %s", keyAA)
			Expect(meta_data_A.KeyA).To(Equal(copy.KeyA))
			userlib.DebugMsg("expect username is %s", alice_username)
			Expect(meta_data_A.Username).To(Equal(copy.Username))
			userlib.DebugMsg("expect FielsStructUUID is %s", file_struct_uuid)
			Expect(meta_data_A.FileStructUUID).To(Equal(copy.FileStructUUID))
		})

	})

	Describe("Test FileStruct Function", func() {

		Specify("test all functions", func() {
			userlib.DebugMsg("Iniializing alice")
			alice_user, err := InitUser(alice_username, default_password)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing file_struct")
			file_struct, err := createFileStruct(alice_user, owner_key)
			Expect(err).To(BeNil())

			file_struct_uuid := createRandomUUID()
			err = saveFileStruct(file_struct, file_struct_uuid)
			Expect(err).To(BeNil())

			copy, err := getFileStruct(file_struct_uuid)
			Expect(err).To(BeNil())

			userlib.DebugMsg("expect owner is %s", file_struct.Owner)
			Expect(copy.Owner).To(Equal(file_struct.Owner))
			userlib.DebugMsg("expect file_struct.FileHead uuid is %s", file_struct.FileHead)
			userlib.DebugMsg("expect copy.FileHead uuid is %s", copy.FileHead)
			Expect(copy.FileHead).To(Equal(file_struct.FileHead))
			Expect(copy.ShareWith).To(Equal(file_struct.ShareWith))
		})
	})

	Describe("Test FileKey functions", func() {
		Specify("test all FileKey functions", func() {

			userlib.DebugMsg("Iniializing alice")
			alice_user, err := InitUser(alice_username, default_password)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create file relate keys")
			file_key := createFileKey()
			keyA := createKeyA()
			file_struct_uuid := createRandomUUID()
			file_uuid := usernameToUUID(alice_user.Username, alice_file)

			userlib.DebugMsg("Create file_struct")
			owner_key := createKeys(alice_user.SourceKey, alice_file)
			file_struct, err := createFileStruct(alice_user, owner_key)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create meta_data")
			meta_data, err := createMetaData(keyA, file_struct_uuid, alice_user.Username)
			Expect(err).To(BeNil())
			err = saveMetaData(file_uuid, meta_data, owner_key)
			Expect(err).To(BeNil())

			userlib.DebugMsg("save file_key")
			err = save_file_key(file_key, keyA, alice_user.Username, file_struct, owner_key)
			Expect(err).To(BeNil())

			// saveFileStruct last when operation is complete
			err = saveFileStruct(file_struct, file_struct_uuid)
			Expect(err).To(BeNil())

			// userlib.DebugMsg("Print ListB")
			// list_b := file_struct.ListB
			// for key, val := range list_b {
			// 	userlib.DebugMsg("username: %s, file_key_uuid: %s", key, val)
			// }

			// userlib.DebugMsg("Load copy of file_struct")
			// file_struct_copy, err := getFileStruct(file_struct_uuid)
			// Expect(err).To(BeNil())

			// userlib.DebugMsg("Load listB of file_struct_copy")
			// list_b_copy := file_struct_copy.ListB
			// for key, val := range list_b_copy {
			// 	userlib.DebugMsg("username: %s, file_key_uuid: %s", key, val)
			// }

			userlib.DebugMsg("load file_key")
			file_key_copy, err := get_file_key(meta_data)
			Expect(err).To(BeNil())

			userlib.DebugMsg("compare file key")
			Expect(file_key).To(Equal(file_key_copy))

			userlib.DebugMsg("compare keyA")
			file_struct_copy, err := getFileStruct(file_struct_uuid)
			Expect(err).To(BeNil())
			key_A_copy, err := getKeyA(file_struct_copy, owner_key, alice_user.Username)
			Expect(err).To(BeNil())
			Expect(key_A_copy).To(Equal(keyA))

		})

	})

	Describe("Test Invites Functions", func() {
		Specify("test enc and dec functions", func() {

			userlib.DebugMsg("create recipient keys")
			recipient_pub, recipient_piv, err := userlib.PKEKeyGen()
			Expect(err).To(BeNil())

			userlib.DebugMsg("create sender keys")
			sender_sk, sender_vk, err := userlib.DSKeyGen()
			Expect(err).To(BeNil())

			file_struct_uuid := createRandomUUID()
			keyA := createKeyA()

			userlib.DebugMsg("create invite")
			invite := createInvite(bob_username, file_struct_uuid, keyA, file_struct_uuid)

			userlib.DebugMsg("save invite")
			invite_uuid, err := saveInvite(invite, recipient_pub, sender_sk)
			Expect(err).To(BeNil())

			userlib.DebugMsg("get the invite auth byte from database")
			auth_byte, ok := userlib.DatastoreGet(invite_uuid)
			Expect(ok).To(BeTrue())

			userlib.DebugMsg("decrypt to get the invite")
			invite_copy, err := decryptInvite(auth_byte, recipient_piv, sender_vk)
			Expect(err).To(BeNil())

			userlib.DebugMsg("check all fields of invite_copy")
			Expect(invite_copy.Sharer_username).To(Equal(bob_username))
			Expect(invite_copy.File_struct_uuid).To(Equal(file_struct_uuid))
			Expect(invite_copy.KeyA).To(Equal(keyA))
			Expect(invite_copy.File_key_uuid).To(Equal(file_struct_uuid))
		})
	})

	Describe("Test createInvitation", func() {
		Specify("Test create multiple invitation on the same person", func() {
			userlib.DebugMsg("Iniializing alice and bob")
			alice_user, err := InitUser(alice_username, default_password)
			Expect(err).To(BeNil())

			file_uuid := usernameToUUID(alice_user.Username, alice_file)
			meta_key := createKeys(alice_user.SourceKey, alice_file)

			bob_user, err := InitUser(bob_username, default_password)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create a file")
			err = alice_user.StoreFile(alice_file, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create the first inviation on Bob")
			_, err = alice_user.CreateInvitation(alice_file, bob_user.Username)
			Expect(err).To(BeNil())

			alice_meta_data, err := getMetaData(file_uuid, meta_key)
			Expect(err).To(BeNil())

			file_struct, err := getFileStruct(alice_meta_data.FileStructUUID)
			Expect(err).To(BeNil())

			userlib.DebugMsg("KeyA of 1st invitation is: ")
			keyA, err := getKeyA(file_struct, meta_key, bob_username)
			Expect(err).To(BeNil())
			userlib.DebugMsg("%s", keyA)

			userlib.DebugMsg("Create the second inviation on Bob")
			_, err = alice_user.CreateInvitation(alice_file, bob_username)
			Expect(err).To(BeNil())

			file_struct, err = getFileStruct(alice_meta_data.FileStructUUID)
			Expect(err).To(BeNil())

			userlib.DebugMsg("KeyA of 2st invitation is: ")
			keyA2, err := getKeyA(file_struct, meta_key, bob_username)
			Expect(err).To(BeNil())
			userlib.DebugMsg("%s", keyA2)

			Expect(keyA).ToNot(Equal(keyA2))

		})
	})

	Describe("Test AcceptInviataion", func() {
		Specify("Test meta_data username after accept inviations", func() {
			userlib.DebugMsg("Iniializing alice, bob, and charlie")
			alice_user, err := InitUser(alice_username, default_password)
			Expect(err).To(BeNil())

			bob_user, err := InitUser(bob_username, default_password)
			Expect(err).To(BeNil())

			charlie_user, err := InitUser(charlie_username, default_password)
			Expect(err).To(BeNil())

			alice_file_uuid := usernameToUUID(alice_user.Username, alice_file)
			bob_file_uuid := usernameToUUID(bob_user.Username, bob_file)
			charlie_file_uuid := usernameToUUID(charlie_user.Username, charlie_file)

			alice_file_meta_key := createKeys(alice_user.SourceKey, alice_file)
			bob_file_meta_key := createKeys(bob_user.SourceKey, bob_file)
			charlie_file_meta_key := createKeys(charlie_user.SourceKey, charlie_file)

			userlib.DebugMsg("Create a file")
			err = alice_user.StoreFile(alice_file, []byte(contentOne))
			Expect(err).To(BeNil())

			alice_meta_data, err := getMetaData(alice_file_uuid, alice_file_meta_key)
			Expect(err).To(BeNil())
			// file_struct_1, err := getFileStruct(alice_meta_data.FileStructUUID)
			// Expect(err).To(BeNil())
			// userlib.DebugMsg("file_struct_1  is %s: ", file_struct_1.Owner)

			userlib.DebugMsg("Create inviation from Alice to Bob")
			bob_invite_ptr, err := alice_user.CreateInvitation(alice_file, bob_user.Username)
			Expect(err).To(BeNil())

			// file_struct_2, err := getFileStruct(alice_meta_data.FileStructUUID)
			// Expect(err).To(BeNil())
			// userlib.DebugMsg("file_struct_2 Owner is %s: ", file_struct_2.Owner)

			userlib.DebugMsg("Bob accepts the invitation")
			err = bob_user.AcceptInvitation(alice_user.Username, bob_invite_ptr, bob_file)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create invitation from Bob to Charlie")
			charlie_invite_ptr, err := bob_user.CreateInvitation(bob_file, charlie_user.Username)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charlie accept the inviaton")
			err = charlie_user.AcceptInvitation(bob_user.Username, charlie_invite_ptr, charlie_file)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get the meta_data for all 3 users")
			bob_meta_data, err := getMetaData(bob_file_uuid, bob_file_meta_key)
			Expect(err).To(BeNil())
			charlie_meta_data, err := getMetaData(charlie_file_uuid, charlie_file_meta_key)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice meta_data.username should be %s", alice_username)
			Expect(alice_meta_data.Username).To(Equal(alice_username))
			userlib.DebugMsg("Bob meta_data.username should be %s", bob_username)
			Expect(bob_meta_data.Username).To(Equal(bob_username))
			userlib.DebugMsg("Charlie meta_data.username should be %s", bob_username)
			Expect(charlie_meta_data.Username).To(Equal(bob_username))

			userlib.DebugMsg("all meta_data.FileStructUUID should be the same")
			Expect(alice_meta_data.FileStructUUID).To(Equal(bob_meta_data.FileStructUUID))
			Expect(alice_meta_data.FileStructUUID).To(Equal(charlie_meta_data.FileStructUUID))
			Expect(bob_meta_data.FileStructUUID).To(Equal(charlie_meta_data.FileStructUUID))

		})
	})

	Describe("Test bandwidth", func() {

		Specify("Test bandwidth for append file", func() {

			userlib.DebugMsg("Iniializing alice")
			alice_user, err := InitUser(alice_username, default_password)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create a file")
			err = alice_user.StoreFile(alice_file, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Append to alice_file 10,000 times")
			i := 0
			var bw0 int
			var bw1000 int
			var bw10000 int
			for i < 10000 {
				if i == 0 {
					bw0 = measureBandwith(func() {
						err = alice_user.AppendToFile(alice_file, []byte(contentTwo))
						Expect(err).To(BeNil())
					})
				} else if i == 1000 {
					bw1000 = measureBandwith(func() {
						err = alice_user.AppendToFile(alice_file, []byte(contentTwo))
						Expect(err).To(BeNil())
					})
				} else if i == 10000-1 {
					bw10000 = measureBandwith(func() {
						err = alice_user.AppendToFile(alice_file, []byte(contentTwo))
						Expect(err).To(BeNil())
					})
				}
				err = alice_user.AppendToFile(alice_file, []byte(contentTwo))
				Expect(err).To(BeNil())
				i++
			}

			userlib.DebugMsg("All bandwith should have the same value")
			userlib.DebugMsg("bw0 is '%d', bw1000 is '%d',  bw10000 is '%d'", bw0, bw1000, bw10000)
			Expect(bw0).To(Equal(bw1000))
			Expect(bw1000).To(Equal(bw10000))

		})

	})

})
