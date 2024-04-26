let character = document.getElementById("character");
let block = document.getElementById("block");

function jump() {
    if (!character.classList.contains("animate")) {
        character.classList.add("animate");
        setTimeout(() => {
            character.classList.remove("animate");
        }, 500);

        // Adjust octopus's position after jumping
        setTimeout(() => {
            character.style.top = "150px";
        }, 250);
    }
}
// Reset character position after the jump animation ends
character.addEventListener("transitionend", () => {
    character.style.top = "130px"; // Reset character position
});

var checkDead = setInterval(function () {
    var characterTop =
        parseInt(
            window.getComputedStyle(character).getPropertyValue("top")
        );
    var characterLeft =
        parseInt(
            window.getComputedStyle(character).getPropertyValue("left")
        );
    var blockLeft =
        parseInt(
            window.getComputedStyle(block).getPropertyValue("left")
        );

    if (blockLeft <= characterLeft + 70 && characterTop >= 150 && characterTop <= 190) {
        block.style.animation = "none";
        alert("caught");
    }
}, 10);
