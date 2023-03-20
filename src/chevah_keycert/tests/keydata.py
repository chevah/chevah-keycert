# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
"""
Data used by test_keys as well as others.
"""
from __future__ import absolute_import, division, unicode_literals

from base64 import decodestring as decodebytes

RSAData = {
    'n': int('269413617238113438198661010376758399219880277968382122687862697'
              '296942471209955603071120391975773283844560230371884389952067978'
              '789684135947515341209478065209455427327369102356204259106807047'
              '964139525310539133073743116175821417513079706301100600025815509'
              '786721808719302671068052414466483676821987505720384645561708425'
              '794379383191274856941628512616355437197560712892001107828247792'
              '561858327085521991407807015047750218508971611590850575870321007'
              '991909043252470730134547038841839367764074379439843108550888709'
              '430958143271417044750314742880542002948053835745429446485015316'
              '60749404403945254975473896534482849256068133525751'),
    'e': int(65537),
    'd': int('420335724286999695680502438485489819800002417295071059780489811'
              '840828351636754206234982682752076205397047218449504537476523960'
              '987613148307573487322720481066677105211155388802079519869249746'
              '774085882219244493290663802569201213676433159425782937159766786'
              '329742053214957933941260042101377175565683849732354700525628975'
              '239000548651346620826136200952740446562751690924335365940810658'
              '931238410612521441739702170503547025018016868116037053013935451'
              '477930426013703886193016416453215950072147440344656137718959053'
              '897268663969428680144841987624962928576808352739627262941675617'
              '7724661940425316604626522633351193810751757014073'),
    'p': int('152689878451107675391723141129365667732639179427453246378763774'
              '448531436802867910180261906924087589684175595016060014593521649'
              '964959248408388984465569934780790357826811592229318702991401054'
              '226302790395714901636384511513449977061729214247279176398290513'
              '085108930550446985490864812445551198848562639933888780317'),
    'q': int('176444974592327996338888725079951900172097062203378367409936859'
              '072670162290963119826394224277287608693818012745872307600855894'
              '647300295516866118620024751601329775653542084052616260193174546'
              '400544176890518564317596334518015173606460860373958663673307503'
              '231977779632583864454001476729233959405710696795574874403'),
    'u': int('936018002388095842969518498561007090965136403384715613439364803'
              '229386793506402222847415019772053080458257034241832795210460612'
              '924445085372678524176842007912276654532773301546269997020970818'
              '155956828553418266110329867222673040098885651348225673298948529'
              '93885224775891490070400861134282266967852120152546563278')
}

DSAData = {
    'g': int("10253261326864117157640690761723586967382334319435778695"
              "29171533815411392477819921538350732400350395446211982054"
              "96512489289702949127531056893725702005035043292195216541"
              "11525058911428414042792836395195432445511200566318251789"
              "10575695836669396181746841141924498545494149998282951407"
              "18645344764026044855941864175"),
    'p': int("10292031726231756443208850082191198787792966516790381991"
              "77502076899763751166291092085666022362525614129374702633"
              "26262930887668422949051881895212412718444016917144560705"
              "45675251775747156453237145919794089496168502517202869160"
              "78674893099371444940800865897607102159386345313384716752"
              "18590012064772045092956919481"),
    'q': int(1393384845225358996250882900535419012502712821577),
    'x': int(1220877188542930584999385210465204342686893855021),
    'y': int("14604423062661947579790240720337570315008549983452208015"
              "39426429789435409684914513123700756086453120500041882809"
              "10283610277194188071619191739512379408443695946763554493"
              "86398594314468629823767964702559709430618263927529765769"
              "10270265745700231533660131769648708944711006508965764877"
              "684264272082256183140297951")
}

ECDatanistp256 = {
  'x': int('762825130203920963171185031449647317742997734817505505433829043'
            '45687059013883'),
  'y': int('815431978646028526322656647694416475343443758943143196810611371'
            '59310646683104'),
  'privateValue': int('3463874347721034170096400845565569825355565567882605'
                        '9678074967909361042656500'),
  'curve': b'ecdsa-sha2-nistp256'
}

ECDatanistp384 = {
  'privateValue': int('280814107134858470598753916394807521398239633534281633982576099083'
                        '35787109896602102090002196616273211495718603965098'),
  'x': int('10036914308591746758780165503819213553101287571902957054148542'
            '504671046744460374996612408381962208627004841444205030'),
  'y': int('17337335659928075994560513699823544906448896792102247714689323'
            '575406618073069185107088229463828921069465902299522926'),
  'curve': b'ecdsa-sha2-nistp384'
}

ECDatanistp521 = {
  'x': int('12944742826257420846659527752683763193401384271391513286022917'
            '29910013082920512632908350502247952686156279140016049549948975'
            '670668730618745449113644014505462'),
  'y': int('10784108810271976186737587749436295782985563640368689081052886'
            '16296815984553198866894145509329328086635278430266482551941240'
            '591605833440825557820439734509311'),
  'privateValue': int('662751235215460886290293902658128847495347691199214706697089140769'
                        '672273950767961331442265530524063943548846724348048614239791498442'
                        '5997823106818915698960565'),
  'curve': b'ecdsa-sha2-nistp521'
}

Ed25519Data = {
  'a': (b'\xf1\x16\xd1\x15J\x1e\x15\x0e\x19^\x19F\xb5\xf2D\r\xb2R\xa0\xae*k'
        b'#\x13sE\xfd@\xd9W{\x8b'),
  'k': (b'7/%\xda\x8d\xd4\xa8\x9ax|a\xf0\x98\x01\xc6\xf4^mg\x05i17Li\r\x05U'
        b'\xbb\xc9DX')
}

privateECDSA_openssh521 = b"""-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAjn0lSVF6QweS4bjOGP9RHwqxUiTastSE0MVuLtFvkxygZqQ712oZ
ewMvqKkxthMQgxzSpGtRBcmkL7RqZ94+18qgBwYFK4EEACOhgYkDgYYABAFpX/6B
mxxglwD+VpEvw0hcyxVzLxNnMGzxZGF7xmNj8nlF7M+TQctdlR2Xv/J+AgIeVGmB
j2p84bkV9jBzrUNJEACsJjttZw8NbUrhxjkLT/3rMNtuwjE4vLja0P7DMTE0EV8X
f09ETdku/z/1tOSSrSvRwmUcM9nQUJtHHAZlr5Q0fw==
-----END EC PRIVATE KEY-----"""

# New format introduced in OpenSSH 6.5
privateECDSA_openssh521_new = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBaV/+gZscYJcA/laRL8NIXMsVcy8T
ZzBs8WRhe8ZjY/J5RezPk0HLXZUdl7/yfgICHlRpgY9qfOG5FfYwc61DSRAArCY7bWcPDW
1K4cY5C0/96zDbbsIxOLy42tD+wzExNBFfF39PRE3ZLv8/9bTkkq0r0cJlHDPZ0FCbRxwG
Za+UNH8AAAEAeRISlnkSEpYAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAWlf/oGbHGCXAP5WkS/DSFzLFXMvE2cwbPFkYXvGY2PyeUXsz5NBy12VHZe/8n4C
Ah5UaYGPanzhuRX2MHOtQ0kQAKwmO21nDw1tSuHGOQtP/esw227CMTi8uNrQ/sMxMTQRXx
d/T0RN2S7/P/W05JKtK9HCZRwz2dBQm0ccBmWvlDR/AAAAQgCOfSVJUXpDB5LhuM4Y/1Ef
CrFSJNqy1ITQxW4u0W+THKBmpDvXahl7Ay+oqTG2ExCDHNKka1EFyaQvtGpn3j7XygAAAA
ABAg==
-----END OPENSSH PRIVATE KEY-----
"""

publicECDSA_openssh521 = (
    b"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACF"
    b"BAFpX/6BmxxglwD+VpEvw0hcyxVzLxNnMGzxZGF7xmNj8nlF7M+TQctdlR2Xv/J+AgIeVGmB"
    b"j2p84bkV9jBzrUNJEACsJjttZw8NbUrhxjkLT/3rMNtuwjE4vLja0P7DMTE0EV8Xf09ETdku"
    b"/z/1tOSSrSvRwmUcM9nQUJtHHAZlr5Q0fw== comment"
)

privateECDSA_openssh384 = b"""-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAtAi7I8j73WCX20qUM5hhHwHuFzYWYYILs2Sh8UZ+awNkARZ/Fu2LU
LLl5RtOQpbWgBwYFK4EEACKhZANiAATU17sA9P5FRwSknKcFsjjsk0+E3CeXPYX0
Tk/M0HK3PpWQWgrO8JdRHP9eFE9O/23P8BumwFt7F/AvPlCzVd35VfraFT0o4cCW
G0RqpQ+np31aKmeJshkcYALEchnU+tQ=
-----END EC PRIVATE KEY-----"""

# New format introduced in OpenSSH 6.5
privateECDSA_openssh384_new = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTU17sA9P5FRwSknKcFsjjsk0+E3CeX
PYX0Tk/M0HK3PpWQWgrO8JdRHP9eFE9O/23P8BumwFt7F/AvPlCzVd35VfraFT0o4cCWG0
RqpQ+np31aKmeJshkcYALEchnU+tQAAADIiktpWIpLaVgAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEE1Ne7APT+RUcEpJynBbI47JNPhNwnlz2F9E5PzNBytz
6VkFoKzvCXURz/XhRPTv9tz/AbpsBbexfwLz5Qs1Xd+VX62hU9KOHAlhtEaqUPp6d9Wipn
ibIZHGACxHIZ1PrUAAAAMC0CLsjyPvdYJfbSpQzmGEfAe4XNhZhgguzZKHxRn5rA2QBFn8
W7YtQsuXlG05CltQAAAAA=
-----END OPENSSH PRIVATE KEY-----
"""

publicECDSA_openssh384 = (
    b"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABh"
    b"BNTXuwD0/kVHBKScpwWyOOyTT4TcJ5c9hfROT8zQcrc+lZBaCs7wl1Ec/14UT07/bc/wG6bA"
    b"W3sX8C8+ULNV3flV+toVPSjhwJYbRGqlD6enfVoqZ4myGRxgAsRyGdT61A== comment"
)

publicECDSA_openssh = (
    b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB"
    b"BKimX1DZ7+Qj0SpfePMbo1pb6yGkAb5l7duC1l855yD7tEfQfqk7bc7v46We1hLMyz6ObUBY"
    b"gkN/34n42F4vpeA= comment"
)

privateECDSA_openssh = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEyU1YOT2JxxofwbJXIjGftdNcJK55aQdNrhIt2xYQz0oAoGCCqGSM49
AwEHoUQDQgAEqKZfUNnv5CPRKl948xujWlvrIaQBvmXt24LWXznnIPu0R9B+qTtt
zu/jpZ7WEszLPo5tQFiCQ3/fifjYXi+l4A==
-----END EC PRIVATE KEY-----"""

# New format introduced in OpenSSH 6.5
privateECDSA_openssh_new = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSopl9Q2e/kI9EqX3jzG6NaW+shpAG+
Ze3bgtZfOecg+7RH0H6pO23O7+OlntYSzMs+jm1AWIJDf9+J+NheL6XgAAAAmCKU4hcilO
IXAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKimX1DZ7+Qj0Spf
ePMbo1pb6yGkAb5l7duC1l855yD7tEfQfqk7bc7v46We1hLMyz6ObUBYgkN/34n42F4vpe
AAAAAgTJTVg5PYnHGh/BslciMZ+101wkrnlpB02uEi3bFhDPQAAAAA
-----END OPENSSH PRIVATE KEY-----
"""

publicEd25519_openssh = (
    b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPEW0RVKHhUOGV4ZRrXyRA2yUqCuKmsjE3NF"
    b"/UDZV3uL comment"
)

# OpenSSH has only ever supported the "new" (v1) format for Ed25519.
privateEd25519_openssh_new = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDxFtEVSh4VDhleGUa18kQNslKgriprIxNzRf1A2Vd7iwAAAJA61eMLOtXj
CwAAAAtzc2gtZWQyNTUxOQAAACDxFtEVSh4VDhleGUa18kQNslKgriprIxNzRf1A2Vd7iw
AAAEA3LyXajdSomnh8YfCYAcb0Xm1nBWkxN0xpDQVVu8lEWPEW0RVKHhUOGV4ZRrXyRA2y
UqCuKmsjE3NF/UDZV3uLAAAAB2NvbW1lbnQBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----"""

publicRSA_openssh = (
    b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVaqx4I9bWG+wloVDEd2NQhEUBVUIUKirg"
    b"0GDu1OmjrUr6OQZehFV1XwA2v2+qKj+DJjfBaS5b/fDz0n3WmM06QHjVyqgYwBGTJAkMgUyP"
    b"95ztExZqpATpSXfD5FVks3loniwI66zoBC0hdwWnju9TMA2l5bs9auIJNm/9NNN9b0b/h9qp"
    b"KSeq/631heY+Grh6HUqx6sBa9zDfH8Kk5O8/kUmWQNUZdy03w17snaY6RKXCpCnd1bqcPUWz"
    b"xiwYZNW6Pd+rf81CrKfxGAugWBViC6QqbkPD5ASfNaNHjkbtM6Vlvbw7KW4CC1ffdOgTtDc1"
    b"foNfICZgptyti8ZseZj3 comment"
)

privateRSA_openssh = b'''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA1WqseCPW1hvsJaFQxHdjUIRFAVVCFCoq4NBg7tTpo61K+jkG
XoRVdV8ANr9vqio/gyY3wWkuW/3w89J91pjNOkB41cqoGMARkyQJDIFMj/ec7RMW
aqQE6Ul3w+RVZLN5aJ4sCOus6AQtIXcFp47vUzANpeW7PWriCTZv/TTTfW9G/4fa
qSknqv+t9YXmPhq4eh1KserAWvcw3x/CpOTvP5FJlkDVGXctN8Ne7J2mOkSlwqQp
3dW6nD1Fs8YsGGTVuj3fq3/NQqyn8RgLoFgVYgukKm5Dw+QEnzWjR45G7TOlZb28
OyluAgtX33ToE7Q3NX6DXyAmYKbcrYvGbHmY9wIDAQABAoIBACFMCGaiKNW0+44P
chuFCQC58k438BxXS+NRf54jp+Q6mFUb6ot6mB682Lqx+YkSGGCs6MwLTglaQGq6
L5n4syRghLnOaZWa+eL8H1FNJxXbKyet77RprL59EOuGR3BztACHlRU7N/nnFOeA
u2geG+bdu3NjuWfmsid/z88wm8KY/dkYNi82LvE9gXqf4QMtR9s0UWI53U/prKiL
2dbzhMQXuXGdBghCeE27xSr0w1jNVSvtvjNfBOp75gQkY/It1z0bbNWcY0MvkoiN
Pm7aGDfYDyVniR25RjReyc7Ei+2SWjMHD9+GCPmS6dvrOAg2yc3NCgFIWzk+esrG
gKnc1DkCgYEA2XAG2OK81HiRUJTUwRuJOGxGZFpRoJoHPUiPA1HMaxKOfRqxZedx
dTngMgV1jRhMr5OxSbFmX3hietEMyuZNQ7Oc9Gt95gyY3M8hYo7VLhLeBK7XJG6D
MaIVokQ9IqliJiK5su1UCp0Ig6cHDf8ZGI7Yqx3aSJwxaBGhZm3j2B0CgYEA+0QX
i6Q2vh43Haf2YWwExKrdeD4HjB4zAq4DFIeDeuWefQhnqPKqvxJwz3Kpp8cLHYjV
IP2cY8pHMFVOi8TP9H8WpJISdKEJwsRunIwz76Xl9+ArrU9cEaoahDdb/Xrqw818
sMjkH1Rjtcev3/QJp/zHJfxc6ZHXksWYHlbTsSMCgYBRr+mSn5QLSoRlPpSzO5IQ
tXS4jMnvyQ4BMvovaBKhAyauz1FoFEwmmyikAjMIX+GncJgBNHleUo7Ezza8H0tV
rOvBU4TH4WGoStSi/0ANgB8SqVDAKhh1lAwGmxZQqEvsQc177/dLyXUCaMSYuIaI
GFpD5wIzlyJkk4MMRSp87QKBgGlmN8ZA3SHFBPOwuD5HlHx2/C3rPzk8lcNDAVHE
Qpfz6Bakxu7s1EkQUDgE7jvN19DMzDJpkAegG1qf/jHNHjp+cR4ZlBpOTwzfX1LV
0Rdu7NectlWd244hX7wkiLb8r6vw76QssNyfhrADEriL4t0PwO4jPUpQ/i+4KUZY
v7YnAoGAZhb5IDTQVCW8YTGsgvvvnDUefkpVAmiVDQqTvh6/4UD6kKdUcDHpePzg
Zrcid5rr3dXSMEbK4tdeQZvPtUg1Uaol3N7bNClIIdvWdPx+5S9T95wJcLnkoHam
rXp0IjScTxfLP+Cq5V6lJ94/pX8Ppoj1FdZfNxeS4NYFSRA7kvY=
-----END RSA PRIVATE KEY-----'''

# Some versions of OpenSSH generate these (slightly different keys): the PKCS#1
# structure is wrapped in an extra ASN.1 SEQUENCE and there's an empty SEQUENCE
# following it. It is not any standard key format and was probably a bug in
# OpenSSH at some point.
privateRSA_openssh_alternate = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEqTCCBKMCAQACggEBANVqrHgj1tYb7CWhUMR3Y1CERQFVQhQqKuDQYO7U6aOtSvo5Bl6EVXVf
ADa/b6oqP4MmN8FpLlv98PPSfdaYzTpAeNXKqBjAEZMkCQyBTI/3nO0TFmqkBOlJd8PkVWSzeWie
LAjrrOgELSF3BaeO71MwDaXluz1q4gk2b/00031vRv+H2qkpJ6r/rfWF5j4auHodSrHqwFr3MN8f
wqTk7z+RSZZA1Rl3LTfDXuydpjpEpcKkKd3Vupw9RbPGLBhk1bo936t/zUKsp/EYC6BYFWILpCpu
Q8PkBJ81o0eORu0zpWW9vDspbgILV9906BO0NzV+g18gJmCm3K2Lxmx5mPcCAwEAAQKCAQAhTAhm
oijVtPuOD3IbhQkAufJON/AcV0vjUX+eI6fkOphVG+qLepgevNi6sfmJEhhgrOjMC04JWkBqui+Z
+LMkYIS5zmmVmvni/B9RTScV2ysnre+0aay+fRDrhkdwc7QAh5UVOzf55xTngLtoHhvm3btzY7ln
5rInf8/PMJvCmP3ZGDYvNi7xPYF6n+EDLUfbNFFiOd1P6ayoi9nW84TEF7lxnQYIQnhNu8Uq9MNY
zVUr7b4zXwTqe+YEJGPyLdc9G2zVnGNDL5KIjT5u2hg32A8lZ4kduUY0XsnOxIvtklozBw/fhgj5
kunb6zgINsnNzQoBSFs5PnrKxoCp3NQ5AoGBANlwBtjivNR4kVCU1MEbiThsRmRaUaCaBz1IjwNR
zGsSjn0asWXncXU54DIFdY0YTK+TsUmxZl94YnrRDMrmTUOznPRrfeYMmNzPIWKO1S4S3gSu1yRu
gzGiFaJEPSKpYiYiubLtVAqdCIOnBw3/GRiO2Ksd2kicMWgRoWZt49gdAoGBAPtEF4ukNr4eNx2n
9mFsBMSq3Xg+B4weMwKuAxSHg3rlnn0IZ6jyqr8ScM9yqafHCx2I1SD9nGPKRzBVTovEz/R/FqSS
EnShCcLEbpyMM++l5ffgK61PXBGqGoQ3W/166sPNfLDI5B9UY7XHr9/0Caf8xyX8XOmR15LFmB5W
07EjAoGAUa/pkp+UC0qEZT6UszuSELV0uIzJ78kOATL6L2gSoQMmrs9RaBRMJpsopAIzCF/hp3CY
ATR5XlKOxM82vB9LVazrwVOEx+FhqErUov9ADYAfEqlQwCoYdZQMBpsWUKhL7EHNe+/3S8l1AmjE
mLiGiBhaQ+cCM5ciZJODDEUqfO0CgYBpZjfGQN0hxQTzsLg+R5R8dvwt6z85PJXDQwFRxEKX8+gW
pMbu7NRJEFA4BO47zdfQzMwyaZAHoBtan/4xzR46fnEeGZQaTk8M319S1dEXbuzXnLZVnduOIV+8
JIi2/K+r8O+kLLDcn4awAxK4i+LdD8DuIz1KUP4vuClGWL+2JwKBgQCFSxt6mxIQN54frV7a/saW
/t81a7k04haXkiYJvb1wIAOnNb0tG6DSB0cr1N6oqAcHG7gEIKcnQTxsOTnpQc7nFx3RTFy8PdIm
Jv5q1v1Icq5G+nvD0xlgRB2lE6eA9WMp1HpdBgcWXfaLPctkOuKEWk2MBi0tnRzrg0x4PXlUzjAA
-----END RSA PRIVATE KEY-----"""

# New format introduced in OpenSSH 6.5
privateRSA_openssh_new = b'''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1WqseCPW1hvsJaFQxHdjUIRFAVVCFCoq4NBg7tTpo61K+jkGXoRV
dV8ANr9vqio/gyY3wWkuW/3w89J91pjNOkB41cqoGMARkyQJDIFMj/ec7RMWaqQE6Ul3w+
RVZLN5aJ4sCOus6AQtIXcFp47vUzANpeW7PWriCTZv/TTTfW9G/4faqSknqv+t9YXmPhq4
eh1KserAWvcw3x/CpOTvP5FJlkDVGXctN8Ne7J2mOkSlwqQp3dW6nD1Fs8YsGGTVuj3fq3
/NQqyn8RgLoFgVYgukKm5Dw+QEnzWjR45G7TOlZb28OyluAgtX33ToE7Q3NX6DXyAmYKbc
rYvGbHmY9wAAA7gXkBoMF5AaDAAAAAdzc2gtcnNhAAABAQDVaqx4I9bWG+wloVDEd2NQhE
UBVUIUKirg0GDu1OmjrUr6OQZehFV1XwA2v2+qKj+DJjfBaS5b/fDz0n3WmM06QHjVyqgY
wBGTJAkMgUyP95ztExZqpATpSXfD5FVks3loniwI66zoBC0hdwWnju9TMA2l5bs9auIJNm
/9NNN9b0b/h9qpKSeq/631heY+Grh6HUqx6sBa9zDfH8Kk5O8/kUmWQNUZdy03w17snaY6
RKXCpCnd1bqcPUWzxiwYZNW6Pd+rf81CrKfxGAugWBViC6QqbkPD5ASfNaNHjkbtM6Vlvb
w7KW4CC1ffdOgTtDc1foNfICZgptyti8ZseZj3AAAAAwEAAQAAAQAhTAhmoijVtPuOD3Ib
hQkAufJON/AcV0vjUX+eI6fkOphVG+qLepgevNi6sfmJEhhgrOjMC04JWkBqui+Z+LMkYI
S5zmmVmvni/B9RTScV2ysnre+0aay+fRDrhkdwc7QAh5UVOzf55xTngLtoHhvm3btzY7ln
5rInf8/PMJvCmP3ZGDYvNi7xPYF6n+EDLUfbNFFiOd1P6ayoi9nW84TEF7lxnQYIQnhNu8
Uq9MNYzVUr7b4zXwTqe+YEJGPyLdc9G2zVnGNDL5KIjT5u2hg32A8lZ4kduUY0XsnOxIvt
klozBw/fhgj5kunb6zgINsnNzQoBSFs5PnrKxoCp3NQ5AAAAgQCFSxt6mxIQN54frV7a/s
aW/t81a7k04haXkiYJvb1wIAOnNb0tG6DSB0cr1N6oqAcHG7gEIKcnQTxsOTnpQc7nFx3R
TFy8PdImJv5q1v1Icq5G+nvD0xlgRB2lE6eA9WMp1HpdBgcWXfaLPctkOuKEWk2MBi0tnR
zrg0x4PXlUzgAAAIEA2XAG2OK81HiRUJTUwRuJOGxGZFpRoJoHPUiPA1HMaxKOfRqxZedx
dTngMgV1jRhMr5OxSbFmX3hietEMyuZNQ7Oc9Gt95gyY3M8hYo7VLhLeBK7XJG6DMaIVok
Q9IqliJiK5su1UCp0Ig6cHDf8ZGI7Yqx3aSJwxaBGhZm3j2B0AAACBAPtEF4ukNr4eNx2n
9mFsBMSq3Xg+B4weMwKuAxSHg3rlnn0IZ6jyqr8ScM9yqafHCx2I1SD9nGPKRzBVTovEz/
R/FqSSEnShCcLEbpyMM++l5ffgK61PXBGqGoQ3W/166sPNfLDI5B9UY7XHr9/0Caf8xyX8
XOmR15LFmB5W07EjAAAAAAEC
-----END OPENSSH PRIVATE KEY-----
'''

# Encrypted with the passphrase 'encrypted'
privateRSA_openssh_encrypted = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,FFFFFFFFFFFFFFFF

p2A1YsHLXkpMVcsEqhh/nCYb5AqL0uMzfEIqc8hpZ/Ub8PtLsypilMkqzYTnZIGS
ouyPjU/WgtR4VaDnutPWdgYaKdixSEmGhKghCtXFySZqCTJ4O8NCczsktYjUK3D4
Jtl90zL6O81WBY6xP76PBQo9lrI/heAetATeyqutc18bwQIGU+gKk32qvfo15DfS
VYiY0Ds4D7F7fd9pz+f5+UbFUCgU+tfDvBrqodYrUgmH7jKoW/CRDCHHyeEIZDbF
mcMwdcKOyw1sRLaPdihRSVx3kOMvIotHKVTkIDMp+0RTNeXzQnp5U2qzsxzTcG/M
UyJN38XXkuvq5VMj2zmmjHzx34w3NK3ZxpZcoaFUqUBlNp2C8hkCLrAa/DWobKqN
5xA1ElrQvli9XXkT/RIuy4Gc10bbGEoJjuxNRibtSxxWd5Bd1E40ocOd4l1ebI8+
w69XvMTnsmHvkBEADGF2zfRszKnMelg+W5NER1UDuNT03i+1cuhp+2AZg8z7niTO
M17XP3ScGVxrQAEYgtxPrPeIpFJvOx2j5Yt78U9Y2WlaAG6DrubbYv2RsMIibhOG
yk139vMdD8FwCey6yMkkhFAJwnBtC22MAWgjmC5c6AF3SRQSjjQXepPsJcLgpOjy
YwjhnL8w56x9kVDUNPw9A9Cqgxo2sty34ATnKrh4h59PsP83LOL6OC5WjbASgZRd
OIBD8RloQPISo+RUF7X0i4kdaHVNPlR0KyapR+3M5BwhQuvEO99IArDV2LNKGzfc
W4ssugm8iyAJlmwmb2yRXIDHXabInWY7XCdGk8J2qPFbDTvnPbiagJBimjVjgpWw
tV3sVlJYqmOqmCDP78J6he04l0vaHtiOWTDEmNCrK7oFMXIIp3XWjOZGPSOJFdPs
6Go3YB+EGWfOQxqkFM28gcqmYfVPF2sa1FbZLz0ffO11Ma/rliZxZu7WdrAXe/tc
BgIQ8etp2PwAK4jCwwVwjIO8FzqQGpS23Y9NY3rfi97ckgYXKESFtXPsMMA+drZd
ThbXvccfh4EPmaqQXKf4WghHiVJ+/yuY1kUIDEl/O0jRZWT7STgBim/Aha1m6qRs
zl1H7hkDbU4solb1GM5oPzbgGTzyBc+z0XxM9iFRM+fMzPB8+yYHTr4kPbVmKBjy
SCovjQQVsHE4YeUGTq6k/NF5cVIRKTW/RlHvzxsky1Zj31MC736jrxGw4KG7VSLZ
fP6F5jj+mXwS7m0v5to42JBZmRJdKUD88QaGE3ncyQ4yleW5bn9Lf9SuzQg1Dhao
3rSA1RuexsHlIAHvGxx/17X+pyygl8DJbt6TBfbLQk9wc707DJTfh5M/bnk9wwIX
l/Hsa1WtylAMW/2MzgiVy83MbYz4+Ss6GQ5W66okWji+NxrnrYEy6q+WgVQanp7X
D+D7oKykqE1Cdvvulvtfl5fh8wlAs8mrUnKPBBUru348u++2lfacLkxRXyT1ooqY
uSNE5nlwFt08N2Ou/bl7yq6QNRMYrRkn+UEfHWCNYDoGMHln2/i6Z1RapQzNarik
tJf7radBz5nBwBjP08YAEACNSQvpsUgdqiuYjLwX7efFXQva2RzqaQ==
-----END RSA PRIVATE KEY-----"""

# Encrypted with the passphrase 'encrypted', and using the new format
# introduced in OpenSSH 6.5
privateRSA_openssh_encrypted_new = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD0f9WAof
DTbmwztb8pdrSeAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDVaqx4I9bW
G+wloVDEd2NQhEUBVUIUKirg0GDu1OmjrUr6OQZehFV1XwA2v2+qKj+DJjfBaS5b/fDz0n
3WmM06QHjVyqgYwBGTJAkMgUyP95ztExZqpATpSXfD5FVks3loniwI66zoBC0hdwWnju9T
MA2l5bs9auIJNm/9NNN9b0b/h9qpKSeq/631heY+Grh6HUqx6sBa9zDfH8Kk5O8/kUmWQN
UZdy03w17snaY6RKXCpCnd1bqcPUWzxiwYZNW6Pd+rf81CrKfxGAugWBViC6QqbkPD5ASf
NaNHjkbtM6Vlvbw7KW4CC1ffdOgTtDc1foNfICZgptyti8ZseZj3AAADwPQaac8s1xX3af
hQTQexj0vEAWDQsLYzDHN9G7W+UP5WHUu7igeu2GqAC/TOnjUXDP73I+EN3n7T3JFeDRfs
U1Z6Zqb0NKHSRVYwDIdIi8qVohFv85g6+xQ01OpaoOzz+vI34OUvCRHQGTgR6L9fQShZyC
McopYMYfbIse6KcqkfxX3KSdG1Pao6Njx/ShFRbgvmALpR/z0EaGCzHCDxpfUyAdnxm621
Jzaf+LverWdN7sfrfMptaS9//9iJb70sL67K+YIB64qhDnA/w9UOQfXGQFL+AEtdM0BPv8
thP1bs7T0yucBl+ZXdrDKVLZfaS3S/w85Jlgfu+a1DG73pOBOuag435iEJ9EnspjXiiydx
GrfSRk2C+/c4fBDZVGFscK5bfQuUUZyU1qOagekxX7WLHFKk9xajnud+nrAN070SeNwlX8
FZ2CI4KGlQfDvVUpKanYn8Kkj3fZ+YBGyx4M+19clF65FKSM0x1Rrh5tAmNT/SNDbSc28m
ASxrBhztzxUFTrIn3tp+uqkJniFLmFsUtiAUmj8fNyE9blykU7dqq+CqpLA872nQ9bOHHA
JsS1oBYmQ0n6AJz8WrYMdcepqWVld6Q8QSD1zdrY/sAWUovuBA1s4oIEXZhpXSS4ZJiMfh
PVktKBwj5bmoG/mmwYLbo0JHntK8N3TGTzTGLq5TpSBBdVvWSWo7tnfEkrFObmhi1uJSrQ
3zfPVP6BguboxBv+oxhaUBK8UOANe6ZwM4vfiu+QN+sZqWymHIfAktz7eWzwlToe4cKpdG
Uv+e3/7Lo2dyMl3nke5HsSUrlsMGPREuGkBih8+o85ii6D+cuCiVtus3f5c78Cir80zLIr
Z0wWvEAjciEvml00DWaA+JIaOrWwvXySaOzFGpCqC9SQjao379bvn9P3b7kVZsy6zBfHqm
bNEJUOuhBZaY8Okz36chh1xqh4sz7m3nsZ3GYGcvM+3mvRY72QnqsQEG0Sp1XYIn2bHa29
tqp7CG9X8J6dqMcPeoPRDWIX9gw7EPl/M0LP6xgewGJ9bgxwle6Mnr9kNITIswjAJqrLec
zx7dfixjAPc42ADqrw/tEdFQcSqxigcfJNKO1LbDBjh+Hk/cSBou2PoxbIcl0qfQfbGcqI
Dbpd695IEuiW9pYR22txNoIi+7cbMsuFHxQ/OqbrX/jCsprGNNJLAjgGsVEI1JnHWDH0db
3UbqbOHAeY3ufoYXNY1utVOIACpW3r9wBw3FjRi04d70VcKr16OXvOAHGN2G++Y+kMya84
Hl/Kt/gA==
-----END OPENSSH PRIVATE KEY-----
"""

# Encrypted with the passphrase 'testxp'. NB: this key was generated by
# OpenSSH, so it doesn't use the same key data as the other keys here.
privateRSA_openssh_encrypted_aes = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0673309A6ACCAB4B77DEE1C1E536AC26

4Ed/a9OgJWHJsne7yOGWeWMzHYKsxuP9w1v0aYcp+puS75wvhHLiUnNwxz0KDi6n
T3YkKLBsoCWS68ApR2J9yeQ6R+EyS+UQDrO9nwqo3DB5BT3Ggt8S1wE7vjNLQD0H
g/SJnlqwsECNhh8aAx+Ag0m3ZKOZiRD5mCkcDQsZET7URSmFytDKOjhFn3u6ZFVB
sXrfpYc6TJtOQlHd/52JB6aAbjt6afSv955Z7enIi+5yEJ5y7oYQTaE5zrFMP7N5
9LbfJFlKXxEddy/DErRLxEjmC+t4svHesoJKc2jjjyNPiOoGGF3kJXea62vsjdNV
gMK5Eged3TBVIk2dv8rtJUvyFeCUtjQ1UJZIebScRR47KrbsIpCmU8I4/uHWm5hW
0mOwvdx1L/mqx/BHqVU9Dw2COhOdLbFxlFI92chkovkmNk4P48ziyVnpm7ME22sE
vfCMsyirdqB1mrL4CSM7FXONv+CgfBfeYVkYW8RfJac9U1L/O+JNn7yee414O/rS
hRYw4UdWnH6Gg6niklVKWNY0ZwUZC8zgm2iqy8YCYuneS37jC+OEKP+/s6HSKuqk
2bzcl3/TcZXNSM815hnFRpz0anuyAsvwPNRyvxG2/DacJHL1f6luV4B0o6W410yf
qXQx01DLo7nuyhJqoH3UGCyyXB+/QUs0mbG2PAEn3f5dVs31JMdbt+PrxURXXjKk
4cexpUcIpqqlfpIRe3RD0sDVbH4OXsGhi2kiTfPZu7mgyFxKopRbn1KwU1qKinfY
EU9O4PoTak/tPT+5jFNhaP+HrURoi/pU8EAUNSktl7xAkHYwkN/9Cm7DeBghgf3n
8+tyCGYDsB5utPD0/Xe9yx0Qhc/kMm4xIyQDyA937dk3mUvLC9vulnAP8I+Izim0
fZ182+D1bWwykoD0997mUHG/AUChWR01V1OLwRyPv2wUtiS8VNG76Y2aqKlgqP1P
V+IvIEqR4ERvSBVFzXNF8Y6j/sVxo8+aZw+d0L1Ns/R55deErGg3B8i/2EqGd3r+
0jps9BqFHHWW87n3VyEB3jWCMj8Vi2EJIfa/7pSaViFIQn8LiBLf+zxG5LTOToK5
xkN42fReDcqi3UNfKNGnv4dsplyTR2hyx65lsj4bRKDGLKOuB1y7iB0AGb0LtcAI
dcsVlcCeUquDXtqKvRnwfIMg+ZunyjqHBhj3qgRgbXbT6zjaSdNnih569aTg0Vup
VykzZ7+n/KVcGLmvX0NesdoI7TKbq4TnEIOynuG5Sf+2GpARO5bjcWKSZeN/Ybgk
gccf8Cqf6XWqiwlWd0B7BR3SymeHIaSymC45wmbgdstrbk7Ppa2Tp9AZku8M2Y7c
8mY9b+onK075/ypiwBm4L4GRNTFLnoNQJXx0OSl4FNRWsn6ztbD+jZhu8Seu10Jw
SEJVJ+gmTKdRLYORJKyqhDet6g7kAxs4EoJ25WsOnX5nNr00rit+NkMPA7xbJT+7
CfI51GQLw7pUPeO2WNt6yZO/YkzZrqvTj5FEwybkUyBv7L0gkqu9wjfDdUw0fVHE
xEm4DxjEoaIp8dW/JOzXQ2EF+WaSOgdYsw3Ac+rnnjnNptCdOEDGP6QBkt+oXj4P
-----END RSA PRIVATE KEY-----"""

publicRSA_lsh = (
    b'{KDEwOnB1YmxpYy1rZXkoMTQ6cnNhLXBrY3MxLXNoYTEoMTpuMjU3OgDVaqx4I9bWG+wloVD'
    b'Ed2NQhEUBVUIUKirg0GDu1OmjrUr6OQZehFV1XwA2v2+qKj+DJjfBaS5b/fDz0n3WmM06QHj'
    b'VyqgYwBGTJAkMgUyP95ztExZqpATpSXfD5FVks3loniwI66zoBC0hdwWnju9TMA2l5bs9auI'
    b'JNm/9NNN9b0b/h9qpKSeq/631heY+Grh6HUqx6sBa9zDfH8Kk5O8/kUmWQNUZdy03w17snaY'
    b'6RKXCpCnd1bqcPUWzxiwYZNW6Pd+rf81CrKfxGAugWBViC6QqbkPD5ASfNaNHjkbtM6Vlvbw'
    b'7KW4CC1ffdOgTtDc1foNfICZgptyti8ZseZj3KSgxOmUzOgEAASkpKQ==}'
)

privateRSA_lsh = (
    b"(11:private-key(9:rsa-pkcs1(1:n257:\x00\xd5j\xacx#\xd6\xd6\x1b\xec%\xa1P"
    b"\xc4wcP\x84E\x01UB\x14**\xe0\xd0`\xee\xd4\xe9\xa3\xadJ\xfa9\x06^\x84Uu_"
    b"\x006\xbfo\xaa*?\x83&7\xc1i.[\xfd\xf0\xf3\xd2}\xd6\x98\xcd:@x\xd5\xca"
    b"\xa8\x18\xc0\x11\x93$\t\x0c\x81L\x8f\xf7\x9c\xed\x13\x16j\xa4\x04\xe9Iw"
    b"\xc3\xe4Ud\xb3yh\x9e,\x08\xeb\xac\xe8\x04-!w\x05\xa7\x8e\xefS0\r\xa5\xe5"
    b"\xbb=j\xe2\t6o\xfd4\xd3}oF\xff\x87\xda\xa9)'\xaa\xff\xad\xf5\x85\xe6>"
    b"\x1a\xb8z\x1dJ\xb1\xea\xc0Z\xf70\xdf\x1f\xc2\xa4\xe4\xef?\x91I\x96@\xd5"
    b"\x19w-7\xc3^\xec\x9d\xa6:D\xa5\xc2\xa4)\xdd\xd5\xba\x9c=E\xb3\xc6,\x18d"
    b"\xd5\xba=\xdf\xab\x7f\xcdB\xac\xa7\xf1\x18\x0b\xa0X\x15b\x0b\xa4*nC\xc3"
    b"\xe4\x04\x9f5\xa3G\x8eF\xed3\xa5e\xbd\xbc;)n\x02\x0bW\xdft\xe8\x13\xb475"
    b"~\x83_ &`\xa6\xdc\xad\x8b\xc6ly\x98\xf7)(1:e3:\x01\x00\x01)(1:d256:!L"
    b"\x08f\xa2(\xd5\xb4\xfb\x8e\x0fr\x1b\x85\t\x00\xb9\xf2N7\xf0\x1cWK\xe3Q"
    b"\x7f\x9e#\xa7\xe4:\x98U\x1b\xea\x8bz\x98\x1e\xbc\xd8\xba\xb1\xf9\x89\x12"
    b"\x18`\xac\xe8\xcc\x0bN\tZ@j\xba/\x99\xf8\xb3$`\x84\xb9\xcei\x95\x9a\xf9"
    b"\xe2\xfc\x1fQM'\x15\xdb+'\xad\xef\xb4i\xac\xbe}\x10\xeb\x86Gps\xb4\x00"
    b"\x87\x95\x15;7\xf9\xe7\x14\xe7\x80\xbbh\x1e\x1b\xe6\xdd\xbbsc\xb9g\xe6"
    b"\xb2'\x7f\xcf\xcf0\x9b\xc2\x98\xfd\xd9\x186/6.\xf1=\x81z\x9f\xe1\x03-G"
    b"\xdb4Qb9\xddO\xe9\xac\xa8\x8b\xd9\xd6\xf3\x84\xc4\x17\xb9q\x9d\x06\x08Bx"
    b"M\xbb\xc5*\xf4\xc3X\xcdU+\xed\xbe3_\x04\xea{\xe6\x04$c\xf2-\xd7=\x1bl"
    b"\xd5\x9ccC/\x92\x88\x8d>n\xda\x187\xd8\x0f%g\x89\x1d\xb9F4^\xc9\xce\xc4"
    b"\x8b\xed\x92Z3\x07\x0f\xdf\x86\x08\xf9\x92\xe9\xdb\xeb8\x086\xc9\xcd\xcd"
    b"\n\x01H[9>z\xca\xc6\x80\xa9\xdc\xd49)(1:p129:\x00\xfbD\x17\x8b\xa46\xbe"
    b"\x1e7\x1d\xa7\xf6al\x04\xc4\xaa\xddx>\x07\x8c\x1e3\x02\xae\x03\x14\x87"
    b"\x83z\xe5\x9e}\x08g\xa8\xf2\xaa\xbf\x12p\xcfr\xa9\xa7\xc7\x0b\x1d\x88"
    b"\xd5 \xfd\x9cc\xcaG0UN\x8b\xc4\xcf\xf4\x7f\x16\xa4\x92\x12t\xa1\t\xc2"
    b"\xc4n\x9c\x8c3\xef\xa5\xe5\xf7\xe0+\xadO\\\x11\xaa\x1a\x847[\xfdz\xea"
    b"\xc3\xcd|\xb0\xc8\xe4\x1fTc\xb5\xc7\xaf\xdf\xf4\t\xa7\xfc\xc7%\xfc\\\xe9"
    b"\x91\xd7\x92\xc5\x98\x1eV\xd3\xb1#)(1:q129:\x00\xd9p\x06\xd8\xe2\xbc\xd4"
    b"x\x91P\x94\xd4\xc1\x1b\x898lFdZQ\xa0\x9a\x07=H\x8f\x03Q\xcck\x12\x8e}"
    b"\x1a\xb1e\xe7qu9\xe02\x05u\x8d\x18L\xaf\x93\xb1I\xb1f_xbz\xd1\x0c\xca"
    b"\xe6MC\xb3\x9c\xf4k}\xe6\x0c\x98\xdc\xcf!b\x8e\xd5.\x12\xde\x04\xae\xd7$"
    b"n\x831\xa2\x15\xa2D=\"\xa9b&\"\xb9\xb2\xedT\n\x9d\x08\x83\xa7\x07\r\xff"
    b"\x19\x18\x8e\xd8\xab\x1d\xdaH\x9c1h\x11\xa1fm\xe3\xd8\x1d)(1:a128:if7"
    b"\xc6@\xdd!\xc5\x04\xf3\xb0\xb8>G\x94|v\xfc-\xeb?9<\x95\xc3C\x01Q\xc4B"
    b"\x97\xf3\xe8\x16\xa4\xc6\xee\xec\xd4I\x10P8\x04\xee;\xcd\xd7\xd0\xcc\xcc"
    b"2i\x90\x07\xa0\x1bZ\x9f\xfe1\xcd\x1e:~q\x1e\x19\x94\x1aNO\x0c\xdf_R\xd5"
    b"\xd1\x17n\xec\xd7\x9c\xb6U\x9d\xdb\x8e!_\xbc$\x88\xb6\xfc\xaf\xab\xf0"
    b"\xef\xa4,\xb0\xdc\x9f\x86\xb0\x03\x12\xb8\x8b\xe2\xdd\x0f\xc0\xee#=JP"
    b"\xfe/\xb8)FX\xbf\xb6')(1:b128:Q\xaf\xe9\x92\x9f\x94\x0bJ\x84e>\x94\xb3;"
    b"\x92\x10\xb5t\xb8\x8c\xc9\xef\xc9\x0e\x012\xfa/h\x12\xa1\x03&\xae\xcfQh"
    b"\x14L&\x9b(\xa4\x023\x08_\xe1\xa7p\x98\x014y^R\x8e\xc4\xcf6\xbc\x1fKU"
    b"\xac\xeb\xc1S\x84\xc7\xe1a\xa8J\xd4\xa2\xff@\r\x80\x1f\x12\xa9P\xc0*\x18"
    b"u\x94\x0c\x06\x9b\x16P\xa8K\xecA\xcd{\xef\xf7K\xc9u\x02h\xc4\x98\xb8\x86"
    b"\x88\x18ZC\xe7\x023\x97\"d\x93\x83\x0cE*|\xed)(1:c128:f\x16\xf9 4\xd0T%"
    b"\xbca1\xac\x82\xfb\xef\x9c5\x1e~JU\x02h\x95\r\n\x93\xbe\x1e\xbf\xe1@\xfa"
    b"\x90\xa7Tp1\xe9x\xfc\xe0f\xb7\"w\x9a\xeb\xdd\xd5\xd20F\xca\xe2\xd7^A\x9b"
    b"\xcf\xb5H5Q\xaa%\xdc\xde\xdb4)H!\xdb\xd6t\xfc~\xe5/S\xf7\x9c\tp\xb9\xe4"
    b"\xa0v\xa6\xadzt\"4\x9cO\x17\xcb?\xe0\xaa\xe5^\xa5\'\xde?\xa5\x7f\x0f\xa6"
    b"\x88\xf5\x15\xd6_7\x17\x92\xe0\xd6\x05I\x10;\x92\xf6)))"
)

privateRSA_agentv3 = (
    b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x00!L"
    b"\x08f\xa2(\xd5\xb4\xfb\x8e\x0fr\x1b\x85\t\x00\xb9\xf2N7\xf0\x1cWK\xe3Q"
    b"\x7f\x9e#\xa7\xe4:\x98U\x1b\xea\x8bz\x98\x1e\xbc\xd8\xba\xb1\xf9\x89\x12"
    b"\x18`\xac\xe8\xcc\x0bN\tZ@j\xba/\x99\xf8\xb3$`\x84\xb9\xcei\x95\x9a\xf9"
    b"\xe2\xfc\x1fQM'\x15\xdb+'\xad\xef\xb4i\xac\xbe}\x10\xeb\x86Gps\xb4\x00"
    b"\x87\x95\x15;7\xf9\xe7\x14\xe7\x80\xbbh\x1e\x1b\xe6\xdd\xbbsc\xb9g\xe6"
    b"\xb2'\x7f\xcf\xcf0\x9b\xc2\x98\xfd\xd9\x186/6.\xf1=\x81z\x9f\xe1\x03-G"
    b"\xdb4Qb9\xddO\xe9\xac\xa8\x8b\xd9\xd6\xf3\x84\xc4\x17\xb9q\x9d\x06\x08Bx"
    b"M\xbb\xc5*\xf4\xc3X\xcdU+\xed\xbe3_\x04\xea{\xe6\x04$c\xf2-\xd7=\x1bl"
    b"\xd5\x9ccC/\x92\x88\x8d>n\xda\x187\xd8\x0f%g\x89\x1d\xb9F4^\xc9\xce\xc4"
    b"\x8b\xed\x92Z3\x07\x0f\xdf\x86\x08\xf9\x92\xe9\xdb\xeb8\x086\xc9\xcd\xcd"
    b"\n\x01H[9>z\xca\xc6\x80\xa9\xdc\xd49\x00\x00\x01\x01\x00\xd5j\xacx#\xd6"
    b"\xd6\x1b\xec%\xa1P\xc4wcP\x84E\x01UB\x14**\xe0\xd0`\xee\xd4\xe9\xa3\xadJ"
    b"\xfa9\x06^\x84Uu_\x006\xbfo\xaa*?\x83&7\xc1i.[\xfd\xf0\xf3\xd2}\xd6\x98"
    b"\xcd:@x\xd5\xca\xa8\x18\xc0\x11\x93$\t\x0c\x81L\x8f\xf7\x9c\xed\x13\x16j"
    b"\xa4\x04\xe9Iw\xc3\xe4Ud\xb3yh\x9e,\x08\xeb\xac\xe8\x04-!w\x05\xa7\x8e"
    b"\xefS0\r\xa5\xe5\xbb=j\xe2\t6o\xfd4\xd3}oF\xff\x87\xda\xa9)'\xaa\xff\xad"
    b"\xf5\x85\xe6>\x1a\xb8z\x1dJ\xb1\xea\xc0Z\xf70\xdf\x1f\xc2\xa4\xe4\xef?"
    b"\x91I\x96@\xd5\x19w-7\xc3^\xec\x9d\xa6:D\xa5\xc2\xa4)\xdd\xd5\xba\x9c=E"
    b"\xb3\xc6,\x18d\xd5\xba=\xdf\xab\x7f\xcdB\xac\xa7\xf1\x18\x0b\xa0X\x15b"
    b"\x0b\xa4*nC\xc3\xe4\x04\x9f5\xa3G\x8eF\xed3\xa5e\xbd\xbc;)n\x02\x0bW\xdf"
    b"t\xe8\x13\xb475~\x83_ &`\xa6\xdc\xad\x8b\xc6ly\x98\xf7\x00\x00\x00\x81"
    b"\x00\x85K\x1bz\x9b\x12\x107\x9e\x1f\xad^\xda\xfe\xc6\x96\xfe\xdf5k\xb94"
    b"\xe2\x16\x97\x92&\t\xbd\xbdp \x03\xa75\xbd-\x1b\xa0\xd2\x07G+\xd4\xde"
    b"\xa8\xa8\x07\x07\x1b\xb8\x04 \xa7'A<l99\xe9A\xce\xe7\x17\x1d\xd1L\\\xbc="
    b"\xd2&&\xfej\xd6\xfdHr\xaeF\xfa{\xc3\xd3\x19`D\x1d\xa5\x13\xa7\x80\xf5c)"
    b"\xd4z]\x06\x07\x16]\xf6\x8b=\xcbd:\xe2\x84ZM\x8c\x06--\x9d\x1c\xeb\x83Lx"
    b"=yT\xce\x00\x00\x00\x81\x00\xd9p\x06\xd8\xe2\xbc\xd4x\x91P\x94\xd4\xc1"
    b"\x1b\x898lFdZQ\xa0\x9a\x07=H\x8f\x03Q\xcck\x12\x8e}\x1a\xb1e\xe7qu9\xe02"
    b"\x05u\x8d\x18L\xaf\x93\xb1I\xb1f_xbz\xd1\x0c\xca\xe6MC\xb3\x9c\xf4k}\xe6"
    b"\x0c\x98\xdc\xcf!b\x8e\xd5.\x12\xde\x04\xae\xd7$n\x831\xa2\x15\xa2D=\""
    b"\xa9b&\"\xb9\xb2\xedT\n\x9d\x08\x83\xa7\x07\r\xff\x19\x18\x8e\xd8\xab"
    b"\x1d\xdaH\x9c1h\x11\xa1fm\xe3\xd8\x1d\x00\x00\x00\x81\x00\xfbD\x17\x8b"
    b"\xa46\xbe\x1e7\x1d\xa7\xf6al\x04\xc4\xaa\xddx>\x07\x8c\x1e3\x02\xae\x03"
    b"\x14\x87\x83z\xe5\x9e}\x08g\xa8\xf2\xaa\xbf\x12p\xcfr\xa9\xa7\xc7\x0b"
    b"\x1d\x88\xd5 \xfd\x9cc\xcaG0UN\x8b\xc4\xcf\xf4\x7f\x16\xa4\x92\x12t\xa1"
    b"\t\xc2\xc4n\x9c\x8c3\xef\xa5\xe5\xf7\xe0+\xadO\\\x11\xaa\x1a\x847[\xfdz"
    b"\xea\xc3\xcd|\xb0\xc8\xe4\x1fTc\xb5\xc7\xaf\xdf\xf4\t\xa7\xfc\xc7%\xfc\\"
    b"\xe9\x91\xd7\x92\xc5\x98\x1eV\xd3\xb1#"
)

publicDSA_openssh = b"""\
ssh-dss AAAAB3NzaC1kc3MAAACBAJKQOsVERVDQIpANHH+JAAylo9\
LvFYmFFVMIuHFGlZpIL7sh3IMkqy+cssINM/lnHD3fmsAyLlUXZtt6PD9LgZRazsPOgptuH+Gu48G\
+yFuE8l0fVVUivos/MmYVJ66qT99htcZKatrTWZnpVW7gFABoqw+he2LZ0gkeU0+Sx9a5AAAAFQD0\
EYmTNaFJ8CS0+vFSF4nYcyEnSQAAAIEAkgLjxHJAE7qFWdTqf7EZngu7jAGmdB9k3YzMHe1ldMxEB\
7zNw5aOnxjhoYLtiHeoEcOk2XOyvnE+VfhIWwWAdOiKRTEZlmizkvhGbq0DCe2EPMXirjqWACI5nD\
ioQX1oEMonR8N3AEO5v9SfBqS2Q9R6OBr6lf04RvwpHZ0UGu8AAACAAhRpxGMIWEyaEh8YnjiazQT\
NEpklRZqeBGo1gotJggNmVaIQNIClGlLyCi359efEUuQcZ9SXxM59P+hecc/GU/GHakW5YWE4dP2G\
gdgMQWC7S6WFIXePGGXqNQDdWxlX8umhenvQqa1PnKrFRhDrJw8Z7GjdHxflsxCEmXPoLN8= \
comment\
"""

privateDSA_openssh = b"""\
-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQCSkDrFREVQ0CKQDRx/iQAMpaPS7xWJhRVTCLhxRpWaSC+7IdyD
JKsvnLLCDTP5Zxw935rAMi5VF2bbejw/S4GUWs7DzoKbbh/hruPBvshbhPJdH1VV
Ir6LPzJmFSeuqk/fYbXGSmra01mZ6VVu4BQAaKsPoXti2dIJHlNPksfWuQIVAPQR
iZM1oUnwJLT68VIXidhzISdJAoGBAJIC48RyQBO6hVnU6n+xGZ4Lu4wBpnQfZN2M
zB3tZXTMRAe8zcOWjp8Y4aGC7Yh3qBHDpNlzsr5xPlX4SFsFgHToikUxGZZos5L4
Rm6tAwnthDzF4q46lgAiOZw4qEF9aBDKJ0fDdwBDub/UnwaktkPUejga+pX9OEb8
KR2dFBrvAoGAAhRpxGMIWEyaEh8YnjiazQTNEpklRZqeBGo1gotJggNmVaIQNICl
GlLyCi359efEUuQcZ9SXxM59P+hecc/GU/GHakW5YWE4dP2GgdgMQWC7S6WFIXeP
GGXqNQDdWxlX8umhenvQqa1PnKrFRhDrJw8Z7GjdHxflsxCEmXPoLN8CFQDV2gbL
czUdxCus0pfEP1bddaXRLQ==
-----END DSA PRIVATE KEY-----\
"""

privateDSA_openssh_new = b"""\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsgAAAAdzc2gtZH
NzAAAAgQCSkDrFREVQ0CKQDRx/iQAMpaPS7xWJhRVTCLhxRpWaSC+7IdyDJKsvnLLCDTP5
Zxw935rAMi5VF2bbejw/S4GUWs7DzoKbbh/hruPBvshbhPJdH1VVIr6LPzJmFSeuqk/fYb
XGSmra01mZ6VVu4BQAaKsPoXti2dIJHlNPksfWuQAAABUA9BGJkzWhSfAktPrxUheJ2HMh
J0kAAACBAJIC48RyQBO6hVnU6n+xGZ4Lu4wBpnQfZN2MzB3tZXTMRAe8zcOWjp8Y4aGC7Y
h3qBHDpNlzsr5xPlX4SFsFgHToikUxGZZos5L4Rm6tAwnthDzF4q46lgAiOZw4qEF9aBDK
J0fDdwBDub/UnwaktkPUejga+pX9OEb8KR2dFBrvAAAAgAIUacRjCFhMmhIfGJ44ms0EzR
KZJUWangRqNYKLSYIDZlWiEDSApRpS8got+fXnxFLkHGfUl8TOfT/oXnHPxlPxh2pFuWFh
OHT9hoHYDEFgu0ulhSF3jxhl6jUA3VsZV/LpoXp70KmtT5yqxUYQ6ycPGexo3R8X5bMQhJ
lz6CzfAAAB2MVcBjzFXAY8AAAAB3NzaC1kc3MAAACBAJKQOsVERVDQIpANHH+JAAylo9Lv
FYmFFVMIuHFGlZpIL7sh3IMkqy+cssINM/lnHD3fmsAyLlUXZtt6PD9LgZRazsPOgptuH+
Gu48G+yFuE8l0fVVUivos/MmYVJ66qT99htcZKatrTWZnpVW7gFABoqw+he2LZ0gkeU0+S
x9a5AAAAFQD0EYmTNaFJ8CS0+vFSF4nYcyEnSQAAAIEAkgLjxHJAE7qFWdTqf7EZngu7jA
GmdB9k3YzMHe1ldMxEB7zNw5aOnxjhoYLtiHeoEcOk2XOyvnE+VfhIWwWAdOiKRTEZlmiz
kvhGbq0DCe2EPMXirjqWACI5nDioQX1oEMonR8N3AEO5v9SfBqS2Q9R6OBr6lf04RvwpHZ
0UGu8AAACAAhRpxGMIWEyaEh8YnjiazQTNEpklRZqeBGo1gotJggNmVaIQNIClGlLyCi35
9efEUuQcZ9SXxM59P+hecc/GU/GHakW5YWE4dP2GgdgMQWC7S6WFIXePGGXqNQDdWxlX8u
mhenvQqa1PnKrFRhDrJw8Z7GjdHxflsxCEmXPoLN8AAAAVANXaBstzNR3EK6zSl8Q/Vt11
pdEtAAAAAAE=
-----END OPENSSH PRIVATE KEY-----
"""

publicDSA_lsh = decodebytes(b"""\
e0tERXdPbkIxWW14cFl5MXJaWGtvTXpwa2MyRW9NVHB3TVRJNU9nQ1NrRHJGUkVWUTBDS1FEUngv
aVFBTXBhUFM3eFdKaFJWVENMaHhScFdhU0MrN0lkeURKS3N2bkxMQ0RUUDVaeHc5MzVyQU1pNVZG
MmJiZWp3L1M0R1VXczdEem9LYmJoL2hydVBCdnNoYmhQSmRIMVZWSXI2TFB6Sm1GU2V1cWsvZlli
WEdTbXJhMDFtWjZWVnU0QlFBYUtzUG9YdGkyZElKSGxOUGtzZld1U2tvTVRweE1qRTZBUFFSaVpN
MW9VbndKTFQ2OFZJWGlkaHpJU2RKS1NneE9tY3hNams2QUpJQzQ4UnlRQk82aFZuVTZuK3hHWjRM
dTR3QnBuUWZaTjJNekIzdFpYVE1SQWU4emNPV2pwOFk0YUdDN1loM3FCSERwTmx6c3I1eFBsWDRT
RnNGZ0hUb2lrVXhHWlpvczVMNFJtNnRBd250aER6RjRxNDZsZ0FpT1p3NHFFRjlhQkRLSjBmRGR3
QkR1Yi9Vbndha3RrUFVlamdhK3BYOU9FYjhLUjJkRkJydktTZ3hPbmt4TWpnNkFoUnB4R01JV0V5
YUVoOFluamlhelFUTkVwa2xSWnFlQkdvMWdvdEpnZ05tVmFJUU5JQ2xHbEx5Q2kzNTllZkVVdVFj
WjlTWHhNNTlQK2hlY2MvR1UvR0hha1c1WVdFNGRQMkdnZGdNUVdDN1M2V0ZJWGVQR0dYcU5RRGRX
eGxYOHVtaGVudlFxYTFQbktyRlJoRHJKdzhaN0dqZEh4ZmxzeENFbVhQb0xOOHBLU2s9fQ==
""")

privateDSA_lsh = decodebytes(b"""\
KDExOnByaXZhdGUta2V5KDM6ZHNhKDE6cDEyOToAkpA6xURFUNAikA0cf4kADKWj0u8ViYUVUwi4
cUaVmkgvuyHcgySrL5yywg0z+WccPd+awDIuVRdm23o8P0uBlFrOw86Cm24f4a7jwb7IW4TyXR9V
VSK+iz8yZhUnrqpP32G1xkpq2tNZmelVbuAUAGirD6F7YtnSCR5TT5LH1rkpKDE6cTIxOgD0EYmT
NaFJ8CS0+vFSF4nYcyEnSSkoMTpnMTI5OgCSAuPEckATuoVZ1Op/sRmeC7uMAaZ0H2TdjMwd7WV0
zEQHvM3Dlo6fGOGhgu2Id6gRw6TZc7K+cT5V+EhbBYB06IpFMRmWaLOS+EZurQMJ7YQ8xeKuOpYA
IjmcOKhBfWgQyidHw3cAQ7m/1J8GpLZD1Ho4GvqV/ThG/CkdnRQa7ykoMTp5MTI4OgIUacRjCFhM
mhIfGJ44ms0EzRKZJUWangRqNYKLSYIDZlWiEDSApRpS8got+fXnxFLkHGfUl8TOfT/oXnHPxlPx
h2pFuWFhOHT9hoHYDEFgu0ulhSF3jxhl6jUA3VsZV/LpoXp70KmtT5yqxUYQ6ycPGexo3R8X5bMQ
hJlz6CzfKSgxOngyMToA1doGy3M1HcQrrNKXxD9W3XWl0S0pKSk=
""")

privateDSA_agentv3 = decodebytes(b"""\
AAAAB3NzaC1kc3MAAACBAJKQOsVERVDQIpANHH+JAAylo9LvFYmFFVMIuHFGlZpIL7sh3IMkqy+c
ssINM/lnHD3fmsAyLlUXZtt6PD9LgZRazsPOgptuH+Gu48G+yFuE8l0fVVUivos/MmYVJ66qT99h
tcZKatrTWZnpVW7gFABoqw+he2LZ0gkeU0+Sx9a5AAAAFQD0EYmTNaFJ8CS0+vFSF4nYcyEnSQAA
AIEAkgLjxHJAE7qFWdTqf7EZngu7jAGmdB9k3YzMHe1ldMxEB7zNw5aOnxjhoYLtiHeoEcOk2XOy
vnE+VfhIWwWAdOiKRTEZlmizkvhGbq0DCe2EPMXirjqWACI5nDioQX1oEMonR8N3AEO5v9SfBqS2
Q9R6OBr6lf04RvwpHZ0UGu8AAACAAhRpxGMIWEyaEh8YnjiazQTNEpklRZqeBGo1gotJggNmVaIQ
NIClGlLyCi359efEUuQcZ9SXxM59P+hecc/GU/GHakW5YWE4dP2GgdgMQWC7S6WFIXePGGXqNQDd
WxlX8umhenvQqa1PnKrFRhDrJw8Z7GjdHxflsxCEmXPoLN8AAAAVANXaBstzNR3EK6zSl8Q/Vt11
pdEt
""")

# Custom code

privateRSA_fingerprint_md5 = '85:25:04:32:58:55:96:9f:57:ee:fb:a8:1a:ea:69:da'

RSAData2 = {
    'n': int('106248668575524741116943830949539894737212779118943280948138'
              '20729711061576321820845393835692814935201176341295575504152775'
              '16685881326038852354459895734875625093273594925884531272867425'
              '864910490065695876046999646807138717162833156501'),
    'e': int(35),
    'd': int('667848773903298372735075508825679338348194611604786337388297'
              '30301040958479737159599618395783408164121679859572188879144827'
              '13602371850869127033494910375212470664166001439410214474266799'
              '85974425203903884190893469297150446322896587555'),
    'q': int('3395694744258061291019136154000709371890447462086362702627'
              '9704149412726577280741108645721676968699696898960891593323'),
    'p': int('3128922844292337321766351031842562691837301298995834258844'
              '4720539204069737532863831050930719431498338835415515173887'),
    'u': int('2777403202132551568802514199893235993376771442611051821485'
              '0278129927603609294283482712900532542110958095343012272938')
    }

DSAData2 = {
    'g': int("10253261326864117157640690761723586967382334319435778695"
              "29171533815411392477819921538350732400350395446211982054"
              "96512489289702949127531056893725702005035043292195216541"
              "11525058911428414042792836395195432445511200566318251789"
              "10575695836669396181746841141924498545494149998282951407"
              "18645344764026044855941864175"),
    'p': int("10292031726231756443208850082191198787792966516790381991"
              "77502076899763751166291092085666022362525614129374702633"
              "26262930887668422949051881895212412718444016917144560705"
              "45675251775747156453237145919794089496168502517202869160"
              "78674893099371444940800865897607102159386345313384716752"
              "18590012064772045092956919481"),
    'q': int(1393384845225358996250882900535419012502712821577),
    'x': int(1220877188542930584999385210465204342686893855021),
    'y': int("14604423062661947579790240720337570315008549983452208015"
              "39426429789435409684914513123700756086453120500041882809"
              "10283610277194188071619191739512379408443695946763554493"
              "86398594314468629823767964702559709430618263927529765769"
              "10270265745700231533660131769648708944711006508965764877"
              "684264272082256183140297951")
    }