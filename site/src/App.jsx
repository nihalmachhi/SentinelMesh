import { useEffect } from "react";
import Header from "./components/layout/Header.jsx";
import Footer from "./components/layout/Footer.jsx";
import Hero from "./components/sections/Hero.jsx";
import Pipeline from "./components/sections/Pipeline.jsx";
import Evidence from "./components/sections/Evidence.jsx";
import Offline from "./components/sections/Offline.jsx";
import Results from "./components/sections/Results.jsx";
import Features from "./components/sections/Features.jsx";
import Scope from "./components/sections/Scope.jsx";
import Faq from "./components/sections/Faq.jsx";
import Start from "./components/sections/Start.jsx";
import FinalCta from "./components/sections/FinalCta.jsx";
import { useSimulation } from "./hooks/useSimulation.js";

export default function App() {
    const sim = useSimulation();
    useEffect(() => {
        document.documentElement.dataset.theme = "dark";
        document.documentElement.dataset.motion = sim.motion ? "on" : "off";
    }, [sim.motion]);
    return (
        <>
            <Header motion={sim.motion} onToggleMotion={sim.toggleMotion} />
            <main id="main">
                <Hero sim={sim} />
                <Pipeline sim={sim} />
                <Evidence sim={sim} />
                <Offline sim={sim} />
                <Results />
                <Features />
                <Scope />
                <Start />
                <Faq />
                <FinalCta />
            </main>
            <Footer />
        </>
    );
}
