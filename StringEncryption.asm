masm
model small
.386

.data
	;input file handling
	input_file_name db 'input.txt', 0
	pointer_input_fname dd input_file_name
	
	;output file handling
	output_file_name db 'output.txt', 0
	pointer_output_fname dd output_file_name
	handle_output_file dw 0
	
	input db 201 dup ('$') ; Stores input from file
	pointer_input dd input
	len dw 0 ; Length of input from file
	counter dw 0 ; Used as an offset in one of the 'encrypting' algorithms
	
	;User interaction
	initText db 'This program encrypts and decrypts a given message.', 0ah, '$'
	menuText db 'Menu:', 0ah, 'Press 1 to encrypt', 0ah, 'Press 2 to decrypt', 0ah, 'Press 3 to save to file', 0ah, 'Press any other symbol to quit', 0ah,'$'
	optionText db 'Choose an option: ', '$'
	encryptionErrorText db  0ah, 'Cannot encrypt further!', 0ah, '$'
	decryptionErrorText db  0ah, 'Cannot decrypt further!', 0ah, '$'
	fileSavedText db 0ah, 'Message Saved', 0ah, '$'
	newLine DB 0ah,0dh,'$'
	chosenOption db 0
	encryptionDepth db 0 ; How many levels of encryption are currently applied to the input (0 == plain text)
	
	
.stack 256h

.code
main: 

	; -----Initialization-----
	xor ax, ax
	mov ax, @data
	mov ds, ax
	mov es, ax
	
	; Attempt to open the input file with the given name
	mov ah, 3dh 
	mov al, 0 ; Read-only mode
	lds dx, pointer_input_fname
	int 21h
	
	jc exit ; CF = 1 => Error when opening
	
	mov bx, ax ; move the handle to the input file to bx
	
	; Attempt to read up to 200 symbols from the file
	mov ah, 3fh
	lds dx, pointer_input
	mov cx, 200
	int 21h
	
	jc exit ; CF = 1 => Error when reading
	mov len, ax ;Save the lenght
	
	mov ah, 3eh ; Attempt to close the file
	int 21h
	jc exit
	
	; -----Print initial messages-----
	mov ah, 9h
	
	;Print a welcome message
	mov dx, offset initText 
	int 21h
	
	;Print the menu text
	mov dx, offset menuText
	int 21h
	
	;Print the option text
	mov dx, offset optionText
	int 21h
	
	core: ; Main cycle
	mov ah, 01h
	int 21h
	call Manage
	jmp core

exit:
	mov ax, 4c00h ; A standard exit 
	int 21h

	Manage proc ; Manage Encryption/Decryption/Save commands
		cmp al, 31h ;Encrypt command
		je callEnc
		cmp al, 32h ;Decrypt command
		je callDec
		cmp al, 33h ;Save command
		je saveRes
		jne exit
		
	callEnc:
		call Encrypt
		jmp printRes
	
	callDec:
		call Decrypt
		jmp printRes
		
	printRes:	
		mov ah, 09h
		mov dx, offset newLine
		int 21h
		
		cmp len, 0 ;
		je printResEx ;Nothing left to print
		
		mov ah, 02h ;Print symbol by symbol to avoid $, breaking the message
		lea si, input
		mov cx, len
		printlp:
			lodsb;
			mov dl, al
			int 21h
			loop printlp
		
		printResEx:
			ret
		
	saveRes:
		;Attempt to open the output file
		mov ah, 3dh 
		mov al, 1 ; Write mode
		lds dx, pointer_output_fname
		int 21h
	
		jc exit ; CF = 1 => Error when opening 
		
		;Attempt to write the current state of the message to the output file
		mov bx, ax ;handle to bx
		lds dx, pointer_input
		mov cx, len
		mov ah, 40h
		int 21h
		jc exit
		
		;Attempt to close the ouput file (handle is already in bx, if opening was successful)
		mov ah, 3eh
		int 21h
		jc exit
			
		mov dx, offset fileSavedText
		mov ah, 09h
		int 21h
			
		ret
	
	Manage endp

	Encrypt proc
		cmp encryptionDepth, 3h ;Check if the highest level of encryption has already been reached
		jge printEncErr 
		
		cmp encryptionDepth, 0h
		je firstLvl
		cmp encryptionDepth, 1h
		je secondLvl
		cmp encryptionDepth, 2h
		je thirdLvl
		
	printEncErr:
		; Print an error message
		mov ah, 9h
		mov dx, offset encryptionErrorText
		int 21h
		ret
		
		firstLvl:
			call SwapSeq
			inc encryptionDepth
			ret
		
		secondLvl:
			call SwapSym
			inc encryptionDepth
			ret
		
		thirdLvl:
			call Invert
			inc encryptionDepth
			ret
	Encrypt endp
	
	Decrypt proc
		cmp encryptionDepth, 0h ; If the encryption depth(level) is 0, we cannot decrypt further
		je printDecErr
		cmp encryptionDepth, 1h
		je downTo0
		cmp encryptionDepth, 2h
		je downTo1
		cmp encryptionDepth, 3h
		je downTo2
		
		printDecErr:
			; Print an error message
			mov ah, 9h
			mov dx, offset decryptionErrorText
			int 21h
			ret
		
		downTo0:
			call SwapSeq
			dec encryptionDepth
			ret
		
		downTo1:
			call SwapSym
			dec encryptionDepth
			ret
			
		downTo2:
			call Invert
			dec encryptionDepth
			ret
	
	Decrypt endp
	
	;-----Encrypting/Decrypting algorithms-----
	Invert proc 				; Invert the bits of each symbol in the string
		cmp len, 0 ;Nothing to encrypt 
		je invertExit
		
		mov cx, len
		lea di, input
		lea si, input
		
	invertLoop:
		lodsb ; Symbol [si] in al. Increments SI after
		not al
		stosb ; Symbol from al to [di]. Increments DI after
		
		loop invertLoop
		mov al, '$' ; Null-terminate the string
		stosb
		
	invertExit:
		ret
	
Invert endp
	
SwapSeq proc ; Swap symbols pairwise sequentially (Example 1234 => 2143)
	lea si, input
	lea di, input
	
	; Divide len by 2, ignore reminder. This calculates the number of pairwise swaps to be made
	mov ax, len
	mov bl, 2h
	div bl
	
	movsx cx, al ;move with zero fill
	
	;Check if the number of swaps to be made is not 0
	cmp cx, 0
	jne swapLoop
	ret
	
swapLoop:
	lodsb ; Load a symbol [si] in al. Increments SI after
	xchg al, [si] ; Swap contents
	stosb ; Store a symbol from al to [di]. Increments DI after
	
	inc si
	inc di
	
	loop swapLoop
	
	ret
SwapSeq endp
	
SwapSym proc ; Swaps symmetric symbols
	lea si, input
	lea di, input
	
	mov ax, len
	mov counter, ax
	dec counter ; We will iterate till null terminating symbol
	
	mov bl, 2h ; We will iterate over the first half of the string only
	div bl

	movsx cx, al ;expand al with zero fill
	
	; If the message length is 0 оr 1, return
	cmp cx, 0 
	jne swapFBLoop 
	ret
	
	swapFBLoop:
	
		mov al, [si] ;get next symbol
		add si, counter ;get the symmetric symbol in the string
		
		xchg al, [si] ;swap
		sub si, counter
		stosb
		
		inc si
		sub counter, 2h ;subtracting 2 because otherwise we would get the same symbol, since SI increments as well
	loop swapFBLoop

	ret
SwapSym endp
	
end main