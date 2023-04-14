const toggle = document.getElementById('toggledark');
const pi = document.getElementById('profilei');

if(localStorage.getItem('theme')==null){
localStorage.setItem('theme','light');
}
let localData = localStorage.getItem('theme');

if (localData=='light'){
    toggle.className = "fa-solid fa-moon";  
    document.body.classList.remove('dark-theme');
    //pi.src="https://t3.gstatic.com/images?q=tbn:ANd9GcQ-aUqsd9xh5Py3rBFvYT09npTJ3IzfBMzoxOjI8wXeMJzTmeK9";
}else if (localData=='dark'){
    toggle.className = "fa-regular fa-sun";  
    document.body.classList.add('dark-theme');
    //pi.src="https://www.iconpacks.net/icons/2/free-user-icon-3296-thumb.png";
}
toggle.addEventListener('click', function () {
    document.body.classList.toggle("dark-theme");
    if (document.body.classList.contains("dark-theme")) {
        toggle.className = "fa-regular fa-sun";
        localStorage.setItem('theme','dark');
//pi.src="https://www.iconpacks.net/icons/2/free-user-icon-3296-thumb.png";

    } else {
        toggle.className = "fa-solid fa-moon";
        localStorage.setItem('theme','light');
        //pi.src="https://t3.gstatic.com/images?q=tbn:ANd9GcQ-aUqsd9xh5Py3rBFvYT09npTJ3IzfBMzoxOjI8wXeMJzTmeK9";
    }
});

console.log('hehheheheheheheh what are u doin!');

