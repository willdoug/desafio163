# desafio163
Este script é utilizado para tentar achar a chave privada de bitcoin do desafio 163.

O desafio consiste em achar por meio de brute-force a chave privada correta, com um saldo de bitcoin, através de uma chave privada incompleta que foi dada inicialmente.

A chave privada incompleta é a seguinte: 4x3x3x4xcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x .
Onde cada "X" deve ser substituido por um caractere hexadecimal.

A cada vídeo, o criador do desafio dá dicas dos valores dos X de acordo com a posição dele na chave privada, por exemplo: O "X" primeiro X=0, o segundo X=B, etc...

Aqui eu criei este script para substituir todos os X desconhecidos por caracteres randomicos e gerar chaves privadas de bitcoin validas, e a partir disso gerar chave publica e então um endereço de bitcoin, para então comparar com o endereço alvo: 1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC .

Ao achar a chave correta o script mostra a chave privada em hexadecimal, a WIF e salva tudo em um arquivo para garantir que possa ser vista posteriormente.
