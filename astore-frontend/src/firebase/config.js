// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCkr54G4ak9ZU6hXx3JcSpdjEuQaRniieU",
  authDomain: "astore-96dac.firebaseapp.com",
  projectId: "astore-96dac",
  storageBucket: "astore-96dac.firebasestorage.app",
  messagingSenderId: "153527661938",
  appId: "1:153527661938:web:3234f200ac52e0b6f059eb",
  measurementId: "G-8V694H3J8P"
};
// Initialize Firebase
export const app = initializeApp(firebaseConfig);
export const analytics = getAnalytics(app);