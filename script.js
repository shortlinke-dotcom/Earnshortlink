// =========================
// PAYMENT SLIDER
// =========================

const sliderTrack = document.querySelector(".slider-track");

if (sliderTrack) {

    let position = 0;
    let speed = 0.6;

    function animateSlider() {

        position -= speed;

        const halfWidth = sliderTrack.scrollWidth / 2;

        if (Math.abs(position) >= halfWidth) {
            position = 0;
        }

        sliderTrack.style.transform =
            `translateX(${position}px)`;

        requestAnimationFrame(animateSlider);
    }

    animateSlider();
}

// =========================
// NAVBAR SCROLL EFFECT
// =========================

const navbar = document.querySelector(".navbar");

window.addEventListener("scroll", () => {

    if (!navbar) return;

    if (window.scrollY > 50) {

        navbar.style.background =
            "rgba(2,8,20,.92)";

        navbar.style.boxShadow =
            "0 10px 30px rgba(0,0,0,.35)";

    } else {

        navbar.style.background =
            "rgba(2,8,20,.55)";

        navbar.style.boxShadow =
            "none";
    }

});

// =========================
// REVEAL ON SCROLL
// =========================

const revealElements = document.querySelectorAll(
    ".feature-card, .security-card, .notice-box"
);

const observer = new IntersectionObserver(

    (entries) => {

        entries.forEach(entry => {

            if (entry.isIntersecting) {

                entry.target.classList.add("show");
            }

        });

    },

    {
        threshold: 0.15
    }

);

revealElements.forEach(el => {

    el.classList.add("hidden");
    observer.observe(el);

});

// =========================
// MOUSE GLOW EFFECT
// =========================

const glow = document.querySelector(".bg-glow");

document.addEventListener("mousemove", (e) => {

    if (!glow) return;

    const x = e.clientX;
    const y = e.clientY;

    glow.style.left = `${x}px`;
    glow.style.top = `${y}px`;

});

// =========================
// PARALLAX HERO
// =========================

const heroLogo =
    document.querySelector(".hero-logo");

window.addEventListener("mousemove", (e) => {

    if (!heroLogo) return;

    const x =
        (window.innerWidth / 2 - e.clientX) / 35;

    const y =
        (window.innerHeight / 2 - e.clientY) / 35;

    heroLogo.style.transform =
        `translate(${x}px, ${y}px)`;
});

// =========================
// BUTTON RIPPLE EFFECT
// =========================

document.querySelectorAll(
    ".login-btn, .register-btn"
).forEach(button => {

    button.addEventListener("click", function (e) {

        const ripple =
            document.createElement("span");

        const rect =
            this.getBoundingClientRect();

        const size =
            Math.max(rect.width, rect.height);

        ripple.style.width =
            ripple.style.height =
            size + "px";

        ripple.style.left =
            e.clientX - rect.left - size / 2 + "px";

        ripple.style.top =
            e.clientY - rect.top - size / 2 + "px";

        ripple.classList.add("ripple");

        this.appendChild(ripple);

        setTimeout(() => {
            ripple.remove();
        }, 600);

    });

});

// =========================
// COUNTER EFFECT
// =========================

function animateValue(el, start, end, duration) {

    let startTime = null;

    function animation(currentTime) {

        if (!startTime)
            startTime = currentTime;

        const progress =
            Math.min(
                (currentTime - startTime) /
                duration,
                1
            );

        el.textContent =
            Math.floor(
                progress * (end - start)
                + start
            );

        if (progress < 1) {
            requestAnimationFrame(animation);
        }
    }

    requestAnimationFrame(animation);
}

// =========================
// LOADING EFFECT
// =========================

window.addEventListener("load", () => {

    document.body.classList.add("loaded");

});

// =========================
// FLOATING CARDS
// =========================

document.querySelectorAll(
    ".feature-card"
).forEach((card, index) => {

    card.style.animation =
        `floatCard ${4 + index % 3}s ease-in-out infinite`;

});

// =========================
// CONSOLE BRANDING
// =========================

console.log(`
███████╗ █████╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗██╔══██╗████╗  ██║
█████╗  ███████║██████╔╝██╔██╗ ██║
██╔══╝  ██╔══██║██╔══██╗██║╚██╗██║
███████╗██║  ██║██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝

EarnShortlink Landing Page
`);
