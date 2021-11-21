namespace LemonCypher

open System
open System.CommandLine
open System.CommandLine.Invocation
open LemonCypher

module Program =
  let password = "5f042e659d16ada62bd286483a753db6" //default password is bad and should be read from commandline

  (*Defining the commands, their parameters, and the handler functions for when they are used*)
  let decryptCommand =
    let cmd = Command("decrypt", "Decrypt Base64 String")
    cmd.Add(Argument<string> (Name = "decryptee", Description = "Base64 encoded string to be decrypted"))
    cmd.Handler <- CommandHandler.Create //Command handler takes a function to be executed and matches command argument names with parameter names
      (fun decryptee ->
        try
          decrypt (aesGen password) decryptee
          |> Console.Write
          0    
        with //Decrypt will throw an exception if the input string isn't base64 encoded.
        | :? System.FormatException ->
          Console.Error.Write "Invalid input string"
          0
      )
    cmd //Implicit return

  let encryptCommand =
    let cmd = Command("encrypt", "Encrypt string")
    cmd.Add(Argument<string> (Name = "encryptee", Description = "String to be encrypted"))
    cmd.Handler <- CommandHandler.Create 
      (fun encryptee ->
        try
          encrypt (aesGen password) encryptee
          |> Console.Write
          0
        with 
        | :? System.FormatException ->
          Console.Error.Write "Invalid input string"
          0
      )
    cmd

  [<EntryPoint>]
  let main argv =
    let root = RootCommand("Encryption app for non-critical data.") //Set up for arg parsing and program description
    root.Add decryptCommand //Add Commands
    root.Add encryptCommand
    root.Invoke argv //Invoke with the actual arguments