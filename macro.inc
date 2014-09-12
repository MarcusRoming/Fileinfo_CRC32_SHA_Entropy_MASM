print MACRO Quoted_Text:VARARG

       LOCAL Txt

          .data

            Txt db Quoted_Text,0

          .code

        invoke StdOut,ADDR Txt

ENDM