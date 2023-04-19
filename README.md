# IDA_iOSkcache_destroyer
vtabstrucyuwu, the destroyer of iOS kernelcaches

# DISCLAIMER, This only works on kernelcaches that are symbolized, so anything iOS 16 and up, or if you have an illegal kernel that was symbolized in the past, you can use it there too :p 

# What is it?
- an IDAPython script that creates structures based on rtti from the kernelcache, generating class info, and recovering vtables that **INHERIT FROM OSMetaClassBase** (I will not figure out how to get vtable information and class info from classes that don't inherit from it, if you want that information, look for a function that creates an object of the class you want to recover, and reconstruct it yourself! It's easy pz promise <3)

# Is it complete?
- Kinda, I have the base script working, however I need to fix up the codebase, complete my lambda parsing, and fix up template parsing to handle more than 1 parameter. Runtime is also pretty bad so I want to decrease it as much as possible

# Will it pay my taxes for me?
- No, but you shouldn't do that anyway

If you encounter any errors, please submit an issue and I will be in contact with you ASAP to ~~silence you, my work is perfect and never wrong~~ fix the issue :)
This is a W.I.P that is 90%~ done, so expect to run into issues
