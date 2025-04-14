import gplay from 'google-play-scraper';
import axios from 'axios';
import cheerio from 'cheerio';

async function fetchPrivacyPolicyText(url) {
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);
        return $('body').text(); // You might need to adjust the selector based on the actual structure of the privacy policy page
    } catch (error) {
        console.error(`Failed to fetch privacy policy text: ${error}`);
        return "Privacy policy text not available";
    }
}

async function fetchAppDetails(pkgName) {
    const appData = {
        privacyPolicyURL: "Not available",
        privacyPolicyText: "Not available",
        category: "Not available",
        rating: "Not available",
        dataSafety: "Not available"
    };

    try {
        const result = await gplay.app({appId: pkgName});
        appData.privacyPolicyURL = result.privacyPolicy || "Not available";
        appData.category = result.genre || "Not available";
        appData.rating = result.score || "Not available";
        if (appData.privacyPolicyURL !== "Not available") {
            appData.privacyPolicyText = await fetchPrivacyPolicyText(appData.privacyPolicyURL);
        }
    } catch (error) {
        console.error(`Failed to fetch basic app details for ${pkgName}:`, error);
    }

    try {
        const dataSafetyDetails = await gplay.datasafety({appId: pkgName});
        appData.dataSafety = dataSafetyDetails || "Not available";
    } catch (error) {
        console.error(`Failed to fetch data safety for ${pkgName}:`, error);
    }

    console.log(JSON.stringify(appData));
}

const pkgName = process.argv[2];
fetchAppDetails(pkgName);
