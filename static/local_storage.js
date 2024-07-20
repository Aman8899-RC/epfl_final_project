// Get the username input element
const username = document.getElementById('username');
const usernamedisp = document.getElementById("usernamedisp");
// Check if the username input element exists
if (username) {
    // Add an event listener to save the name to localStorage when the input value changes
    username.addEventListener('input', () => {
        localStorage.setItem('name', username.value);
    });
}


const usernamelocalstorage = localStorage.getItem('name');
let newtext = document.createElement("p");
newtext.innerHTML = usernamelocalstorage;

usernamedisp.append(newtext)