function ord(char){
    return char.charCodeAt()
}

function chr(num){
    return String.fromCharCode(num)
}

function ch2ord(ch){
    return ord(ch)-ord("A")
}
function ord2ch(num){
    return chr(num+ord("A"))
}

const charlist="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

class Reflector{
    constructor(wiring){
        this.wiring=wiring
    }
    encipher(key){
        var index=(ord(key)-ord('A'))%26
        var letter=this.wiring[index]
        return letter
    }
}

class Rotor{
    constructor(wiring,notchs){
        this.wiring=wiring
        this.notchs=notchs
        this.state="A"
        this.ring="A"
        this.rwiring = new Array(26)
        for(var i=0;i<26;i++){
            this.rwiring[ord(this.wiring[i]) - ord('A')]= chr(ord('A') + i)
        } 
    }
    encipher_right(key){
        var shift = (ord(this.state) - ord(this.ring))
        var index = (ord(key) - ord('A'))%26
        index = (index + shift)%26

        var letter = this.wiring[index]
        var out = chr(ord('A')+(ord(letter) - ord('A') +26 - shift)%26)
        // #return letter
        return out
    }
    encipher_left(key){
        // console.log(key)
        var shift = (ord(this.state) - ord(this.ring))
        var index = (ord(key) - ord('A'))%26
        index = (index + shift)%26

        var letter = this.rwiring[index]
        var out = chr(ord('A')+(ord(letter) - ord('A') + 26 - shift)%26)
        // #return letter
        return out
    }
    notch(offset=1){
        this.state = chr((ord(this.state) + offset - ord('A')) % 26 + ord('A'))
        // notchnext = this.state === this.notchs
        // return notchnext
    }
    is_in_turnover_pos(){
        return chr((ord(this.state) + 1 - ord('A')) % 26 + ord('A')) === this.notchs
    }
}

class Enigma{
    constructor(ref, r1, r2, r3, key="AAA", plugs="", ring="AAA"){
        this.reflector=ref
        this.rotor1=r1
        this.rotor2=r2
        this.rotor3=r3

        this.rotor1.state = key[0]
        this.rotor2.state = key[1]
        this.rotor3.state = key[2]
        this.rotor1.ring = ring[0]
        this.rotor2.ring = ring[1]
        this.rotor3.ring = ring[2]
        this.reflector.state = 'A' 

        var plugboard_settings= plugs.split(" ")
        if(plugs==="")
            plugboard_settings=[]

        var alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        this.alpha_out = Array(26)
        for(var i=0;i<26;i++){
            this.alpha_out[i] = alpha[i]
        }
        for(var i=0;i<plugboard_settings.length;i++){
            this.alpha_out[ord(plugboard_settings[i][0])-ord('A')] = plugboard_settings[i][1]
            this.alpha_out[ord(plugboard_settings[i][1])-ord('A')] = plugboard_settings[i][0]
        }
    }

    encipher(plaintext_in){

        var plaintext=""
        var cipher=""
        var ciphertext=""
        for(var i=0;i<plaintext_in.length;i++){
            plaintext+=this.alpha_out[ord(plaintext_in[i])-ord('A')]
        }
        for(var i=0;i<plaintext.length;i++){

            if(this.rotor2.is_in_turnover_pos() && this.rotor1.is_in_turnover_pos()){
                this.rotor3.notch()
            }
            if(this.rotor1.is_in_turnover_pos()){
                this.rotor2.notch()
            }

            this.rotor1.notch()

            // console.log(plaintext[i])
            var t = this.rotor1.encipher_right(plaintext[i])
            t = this.rotor2.encipher_right(t)
            t = this.rotor3.encipher_right(t)
            t = this.reflector.encipher(t)
            t = this.rotor3.encipher_left(t)
            t = this.rotor2.encipher_left(t)
            t = this.rotor1.encipher_left(t)
            ciphertext += t
        }
        for(var i=0;i<ciphertext.length;i++){
            cipher+=this.alpha_out[ord(ciphertext[i])-ord('A')]
        }
        return cipher
    }
    
}

class SwitchMatchine{
    constructor(c,duandian,datekey,A,B,C){
        this.duandian=duandian
        this.table=[]
        var off1=(c+ch2ord(datekey[0]))%26
        var off2=Math.floor((c+ch2ord(datekey[0]))/26)
        var off3=Math.floor((ch2ord(datekey[1])+off2)/26)
        var k1=ord2ch(off1)
        var k2=ord2ch((ch2ord(datekey[1])+off2)%26)
        var k3=ord2ch((ch2ord(datekey[2])+off3)%26)
        var myEnigma=new Enigma(myReflector,myrotors[A],myrotors[B],myrotors[C],k1+k2+k3)
        for(var i=0;i<26;i++){
            var ctx=myEnigma.encipher(ord2ch(i))
            myEnigma.rotor1.state=k1
            myEnigma.rotor2.state=k2
            myEnigma.rotor3.state=k3
            this.table.push(ctx[0])
        }
    }
    
    getValue(chi,chj){
        var pi=ord2ch(chi) === this.duandian[0] ? this.duandian[1]:this.duandian[0]
        return [ch2ord(pi),ch2ord(this.table[chj])]
    }
}




function bombcrack(k,plaintext,ciphertext,pos,choicech,choicej,A,B,C){
    function dfs(ci,cj){
        var arr;
        if(bombMartix[ci][cj] !== 0){
            return
        }
        // console.log(ci,cj)
        bombMartix[ci][cj]=1
        dfs(cj,ci)
        for(var i=0;i<smlist[ci].length;i++){
            arr=smlist[ci][i].getValue(ci,cj)
            // console.log(arr)
            dfs(arr[0],arr[1])
        }
    }

    var smlist=[]
    for(var i=0;i<26;i++){
        smlist.push([])
    }
    for(var i=0;i<plaintext.length;i++){
        var sm=new SwitchMatchine(i+pos,[plaintext[i],ciphertext[i]],k,A,B,C)
        smlist[ch2ord(plaintext[i])].push(sm)
        smlist[ch2ord(ciphertext[i])].push(sm)
    }
    // console.log(smlist)
    var plugins=[]
    var bombMartix=[]
    for(var i=0;i<26;i++){
        var arr=[]
        for(var j=0;j<26;j++){
            arr.push(0)
        }
        bombMartix.push(arr)
    }
    dfs(choicech,choicej)
    // console.log(bombMartix)
    for(var i=0;i<26;i++){
        var sum=0
        for(var j=0;j<26;j++){
            sum+=bombMartix[i][j]
        }
        if(sum==26){
            return [false]
        }
        if(sum==25&&choicech==i){
            for(var j=0;j<26;j++){
                if(bombMartix[choicech][j]==0){
                    return [true,j]
                }
            }
        }
        if(sum==1&&choicech==i){
            for(var j=0;j<26;j++){
                for(var m=0;m<26;m++){
                    if(bombMartix[j][m]==1 && j!==m && plugins.indexOf(ord2ch(m)+ord2ch(j))==-1){
                        plugins.push(ord2ch(j)+ord2ch(m))
                    }
                }
            }
            return [true,plugins]
        }
    }

    return [true,-1]
}

var keylist=[]
for(var i=0;i<26;i++){
    for(var j=0;j<26;j++){
        for(var k=0;k<26;k++){
            keylist.push(charlist[i]+charlist[j]+charlist[k])
        }
    }
}


var myReflector=new Reflector("WOEHCKYDMTFRIQBZNLVJXSAUGP")
var myrotor1=new Rotor('UHQAOFBEPIKZSXNCWLGJMVRYDT',"A")
var myrotor2=new Rotor('RIKHFBUJDNCGWSMZVXEQATOLYP',"A")
var myrotor3=new Rotor('ENQXUJSIVGOMRLHYCDKTPWAFZB',"A")
var myrotor4=new Rotor('JECGYWNDPQUSXZMKHRLTAVFOIB',"A")
var myrotor5=new Rotor('EYDBNSFAPJTMGURLOIWCHXQZKV',"A")
var myrotors=[myrotor1,myrotor2,myrotor3,myrotor4,myrotor5]// console.log(keylist)
// var myEnigma=new Enigma(myReflector,myrotor1,myrotor2,myrotor3,"NOY","RY FE LA PW MD XH KI TU")
// console.log(myEnigma.encipher("KEINEBESONDERNEREIGNISSEYHIJNFSZUQBIEFUGNVIF"))

var plaintext="THEWEATHERTODAYIS"

var cip="PDKLANKROFRLUAOQAPIBMLOXHAULBSHBSURPWKHFCXTYOPF"
var pos=22
var ciphertext="OXHAULBSHBSURPWKH"
var choicech=7
var t1=Date.now()
var resultkey,plugins
var choicej=0;


for (var i = 0; i < 5; i++) {
    for (var j = 0; j < 5; j++) {
        if (j == i) continue;
        for (var k = 0; k < 5; k++) {
            if (k == i || k == j) continue;
            // console.log(i, j, k);
            for (var u = 0; u < keylist.length; u++) {
                var res = bombcrack(keylist[u], plaintext, ciphertext, pos, choicech, choicej,i,j,k);
                if (res[0]) {
                    resultkey = keylist[u];
                    console.log(resultkey);
                    if (res[1] == -1) {
                        console.log("error");
                    } else {
                        res = bombcrack(resultkey, plaintext, ciphertext, pos, choicech, res[1],i,j,k);
                        plugins = res[1].join(" ");
                    }
                    var myEnigma = new Enigma(myReflector, myrotors[i], myrotors[j], myrotors[k], resultkey, plugins);
                    console.log(keylist[u], plugins);
                    console.log(i,j,k,myEnigma.encipher(cip));
                    var deltatime=(Date.now()-t1)/1000;
                    console.log(resultkey+"  "+deltatime);
                }
            }
        }
    }
}
// var deltatime=(Date.now()-t1)/1000
// alert(resultkey+"  "+deltatime)
