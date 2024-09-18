var profile_page = document.getElementById('profile');
var files_page = document.getElementById('my_files');
var password_page = document.getElementById('password_page');
var hom = document.getElementById('home');
var image = document.getElementById('iris-image');

function profile(){
profile_page.style.display='block';
password_page.style.display='none';
files_page.style.display='none';
hom.style.display='none';
}

var toggled = false;
function view_iris(){

if (!toggled){
toggled = true;
image.style.display='inline';
return;
}
if (toggled){
toggled = false;
image.style.display = 'none';
return;
}
}


function password(){
if (!toggled){
toggled = true;
password_page.style.display='inline';
return;
}
if (toggled);{
toggled = false;
password_page.style.display='none';
return;
}

profile_page.style.display='inline';
files_page.style.display='none';
hom.style.display='none';
}

function files(){
files_page.style.display='inline';
profile_page.style.display='none';
password_page.style.display='none';
hom.style.display='none';

}



//var upload_page = document.getElementById('upload');
//var about_page = document.getElementById('about');

//var color = document.getElementById('color');

//function home(){
//profile_page.style.display='none';
//password_page.style.display='none';
//about_page.style.display='none';
//files_page.style.display='none';
//hom.style.display='block';
//}


//function about(){
//about_page.style.display='block';
//upload_page.style.display='none';
//profile_page.style.display='inline';
//password_page.style.display='none';
//files_page.style.display='none';
//hom.style.display='none';
//}






//function upload(){
//upload_page.style.display='inline';
//profile_page.style.display='inline';
//password_page.style.display='none';
//about_page.style.display='none';
//files_page.style.display='none';
//hom.style.display='none';
//
//}






