function biletTrimitere() {

    if (document.getElementById("bilet").checked == true){
        document.getElementById("radiologie").style.visibility = "visible";
        document.getElementById("labo").style.visibility = "visible";
        document.getElementById("spital").style.visibility = "visible";
        document.getElementById("other").style.visibility = "visible";

        document.getElementById("labelradiologie").style.visibility = "visible";
        document.getElementById("labellabo").style.visibility = "visible";
        document.getElementById("labelspital").style.visibility = "visible";
        document.getElementById("labelother").style.visibility = "visible";

    } else {
        document.getElementById("radiologie").style.visibility = "hidden";
        document.getElementById("labo").style.visibility = "hidden";
        document.getElementById("spital").style.visibility = "hidden";
        document.getElementById("other").style.visibility = "hidden";

        document.getElementById("labelradiologie").style.visibility = "hidden";
        document.getElementById("labellabo").style.visibility = "hidden";
        document.getElementById("labelspital").style.visibility = "hidden";
        document.getElementById("labelother").style.visibility = "hidden";
    }
}
function scrisoareMedicala() {

    if (document.getElementById("scrisoare").checked == true){
        document.getElementById("medicamente").style.visibility = "visible";

        document.getElementById("labelmedicamente").style.visibility = "visible";

    } else {
        document.getElementById("medicamente").style.visibility = "hidden";

        document.getElementById("labelmedicamente").style.visibility = "hidden";
    }
}

function Medic() {

    if (document.getElementById("beMedic").checked == true){
        document.getElementById("labelcabinet").style.visibility = "visible";

        document.getElementById("inputcabinet").style.visibility = "visible";

    } else {
        document.getElementById("labelcabinet").style.visibility = "hidden";

        document.getElementById("inputcabinet").style.visibility = "hidden";
    }
}

function selected(){
    if(document.getElementById("beMedic").checked == true){
        document.getElementById("beSecretary").checked=false;
    }
    if(document.getElementById("beSecretary").checked == true){
        document.getElementById("beMedic").checked=false;
    }
}