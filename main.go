//GoHash is a tool to recursivly hash files in a directory
package main

import (
	"bufio"
	"crypto"
	_ "crypto/MD5"
	_ "crypto/SHA1"
	_ "crypto/SHA256"
	_ "crypto/SHA512"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Plan is to recursivly search some directories (argv1):
//  1. ignore files w/ certain names
//  5. hash files that have been included
//  6. write log file

// Keyz is our global list of files to stage for exfil that we are tracking
var Keyz []string
var ignoreNames = []string{"Keychains", ".vmdk", ".vmem", ".npm", ".vscode", ".dmg", "man1", ".ova", ".iso"}

func main() {

	if len(os.Args) < 3 {
		fmt.Println("./GoHash [directory to recursivly search] [out file]")
	} else {
		// First arg, the directory we will recursivly search
		pathToDir := os.Args[1]
		// Second arg, location we will write our log file
		outFile := os.Args[2]
		// Third arg will be the hash format we will use
		hashFormat := os.Args[3]

		// Start recursive search
		searchForFiles(pathToDir)
		if Keyz != nil {
			err := HashFiles(outFile, Keyz, hashFormat)
			if err != nil {
				fmt.Println("error writing log file")
			} else {
				fmt.Println("wrote hash log file")
			}
		} else {
			fmt.Println("no files found")
		}
	}
}

// searchForFiles is a private function that recurses through directories, running our searchFileForCriteria function on every file
func searchForFiles(pathToDir string) {
	files, err := ioutil.ReadDir(pathToDir)
	if err != nil {
		fmt.Println(err)
		return
	}
	// loop all files in current dir, throw away the index var
	for _, file := range files {
		if stringLooper(file.Name(), ignoreNames) {
			//fmt.Printf("--DEBUG-- the file %s%s, matched for an ignore file name! excluding file!!", pathToDir, file.Name())
		} else {
			//fmt.Println(file.Name())
			if file.IsDir() {
				//fmt.Println("--DEBUG-- File is a dir, recurse time!")
				// Need to add the tailing slash for new base directory
				dirName := file.Name() + "/"
				fullPath := strings.Join([]string{pathToDir, dirName}, "")
				// Recurse into the new base directory (note, this makes it a depth first search)
				searchForFiles(fullPath)
			} else {
				fullPath := strings.Join([]string{pathToDir, file.Name()}, "")
				//fmt.Printf("--DEBUG-- The file at %s, is worth hashing\n", fullPath)
				Keyz = append(Keyz, fullPath)
			}
		}
	}
}

// A function to loop over our string slices and match any of our globally defined content
func stringLooper(target string, list []string) bool {
	for _, loot := range list {
		if strings.Contains(target, loot) {
			//fmt.Printf("the exact content that matched is : %s \n", loot)
			return true
		}
	}
	return false
}

// HashFiles takes one or many files, hashes them, writes to a logfile
func HashFiles(filename string, files []string, hashType string) error {
	newFile, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	datawriter := bufio.NewWriter(newFile)
	defer datawriter.Flush()
	defer newFile.Close()

	for _, file := range files {
		targetFile, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		// Get the file hash
		//fmt.Printf("--DEBUG-- Hashing the file at %s, with %s now\n", file, hashType)
		result, _, err := generateHash(targetFile, hashType)
		if err != nil {
			return err
		}
		_, _ = datawriter.WriteString(fmt.Sprintf("Hashed "+file+" with %s:"+" %x"+"\n", hashType, result))
	}
	return nil

}

func generateHash(data []byte, hashType string) ([]byte, crypto.Hash, error) {

	var hashT2 crypto.Hash
	switch hashType {
	case "md5":
		hashT2 = crypto.MD5
	case "sha1":
		hashT2 = crypto.SHA1
	case "sha256":
		hashT2 = crypto.SHA256
	case "sha512":
		hashT2 = crypto.SHA512
	default:
		return nil, hashT2, fmt.Errorf("unsupported Algorithm.Hash in signature: %s", hashType)
	}

	hasherT := hashT2.New()
	if _, err := hasherT.Write(data); err != nil {
		return nil, hashT2, fmt.Errorf("failed to write to hasher: %v", err)
	}
	return hasherT.Sum([]byte{}), hashT2, nil
}
