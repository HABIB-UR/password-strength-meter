import streamlit as st
import re
from typing import Tuple
import random
import string
import json
import math
from datetime import datetime, timedelta
from zxcvbn import zxcvbn 

import plotly.graph_objects as go 
from collections import Counter

# Common passwords list (you can expand this)
COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "welcome",
    "123456789", "12345678", "abc123", "password1", "admin123"
}

def generate_password(length: int = 16) -> str:
    """Generate a strong random password"""
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*(),.?\":{}|<>"
    
    # Ensure at least one character from each set
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special)
    ]
    
    # Fill the rest of the password length with random characters
    all_characters = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password.append(random.choice(all_characters))
    
    # Shuffle the password characters
    random.shuffle(password)
    
    # Join and return the password
    return ''.join(password)

def create_password_visualization(password: str):
    """Create a visual representation of password character distribution"""
    char_count = Counter(password)
    
    # Create separate counts for different character types
    lowercase = {c: n for c, n in char_count.items() if c.islower()}
    uppercase = {c: n for c, n in char_count.items() if c.isupper()}
    digits = {c: n for c, n in char_count.items() if c.isdigit()}
    special = {c: n for c, n in char_count.items() if not c.isalnum()}
    
    fig = go.Figure()
    
    # Add bars for each character type
    colors = {'lowercase': 'blue', 'uppercase': 'green', 
             'digits': 'orange', 'special': 'red'}
    
    for char_type, chars in [('lowercase', lowercase), ('uppercase', uppercase),
                           ('digits', digits), ('special', special)]:
        if chars:
            fig.add_trace(go.Bar(
                x=list(chars.keys()),
                y=list(chars.values()),
                name=char_type,
                marker_color=colors[char_type]
            ))
    
    fig.update_layout(
        title="Character Distribution",
        xaxis_title="Characters",
        yaxis_title="Frequency",
        showlegend=True,
        height=300
    )
    
    return fig

def estimate_crack_cost(entropy: float) -> float:
    """Estimate the cost to crack the password using cloud computing"""
    # Assuming AWS EC2 p3.2xlarge instance at $3.06/hour
    hashes_per_second = 100_000_000  # 100M hashes/second
    possible_combinations = 2 ** entropy
    seconds_to_crack = possible_combinations / hashes_per_second
    hours_to_crack = seconds_to_crack / 3600
    return round(hours_to_crack * 3.06, 2)

def suggest_similar_strong_password(password: str) -> str:
    """Suggest a stronger version of the user's password"""
    # Keep the basic structure but enhance it
    enhanced = list(password)
    
    # Add complexity if missing
    if not any(c.isupper() for c in password):
        enhanced[0] = enhanced[0].upper()
    if not any(c.isdigit() for c in password):
        enhanced.append('9')
    if not any(c in "!@#$%^&*" for c in password):
        enhanced.append('!')
    
    return ''.join(enhanced)

def check_password_strength(password: str) -> Tuple[int, list, float]:
    """
    Check password strength and return score, feedback, and entropy
    """
    score = 0
    feedback = []
    
    # Calculate entropy
    entropy = calculate_entropy(password)
    
    # Add zxcvbn analysis
    zxcvbn_result = zxcvbn.zxcvbn(password)
    
    # Check if password is common
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("❌ This is a commonly used password")
        return 0, feedback, entropy
    
    # Length check
    if len(password) < 8:
        feedback.append("❌ Password should be at least 8 characters long")
    elif len(password) >= 12:
        score += 2
        feedback.append("✅ Good length")
    else:
        score += 1
        feedback.append("⚠️ Consider using a longer password")
    
    # Check for numbers
    if re.search(r"\d", password):
        score += 1
        feedback.append("✅ Contains numbers")
    else:
        feedback.append("❌ Add numbers")
    
    # Check for lowercase
    if re.search(r"[a-z]", password):
        score += 1
        feedback.append("✅ Contains lowercase letters")
    else:
        feedback.append("❌ Add lowercase letters")
    
    # Check for uppercase
    if re.search(r"[A-Z]", password):
        score += 1
        feedback.append("✅ Contains uppercase letters")
    else:
        feedback.append("❌ Add uppercase letters")
    
    # Check for special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
        feedback.append("✅ Contains special characters")
    else:
        feedback.append("❌ Add special characters")
    
    # Check for repeated characters
    if re.search(r"(.)\1{2,}", password):
        feedback.append("⚠️ Contains repeated characters")
        score -= 1
    
    # Check for sequential characters
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", 
                 password.lower()):
        feedback.append("⚠️ Contains sequential letters")
        score -= 1
    
    # Check for keyboard patterns (expanded)
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', '098765']
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        feedback.append("⚠️ Contains keyboard pattern")
        score -= 1
    
    # Check for repeating patterns
    if any(password.count(password[i:i+2]) > 1 for i in range(len(password)-1)):
        feedback.append("⚠️ Contains repeating patterns")
        score -= 1
    
    # Check for palindromes
    if password.lower() == password.lower()[::-1] and len(password) > 2:
        feedback.append("⚠️ Password is a palindrome")
        score -= 1
    
    # Add more sophisticated checks
    if zxcvbn_result['score'] < 3:
        feedback.extend([f"❌ {suggestion}" for suggestion in zxcvbn_result['feedback']['suggestions']])
    
    return max(0, score), feedback, entropy

def get_password_score_color(score: int) -> str:
    """
    Return color based on password score
    """
    if score < 2:
        return "red"
    elif score < 3:
        return "orange"
    elif score < 5:
        return "yellow"
    else:
        return "green"

def get_strength_description(score: int) -> str:
    """Return detailed strength description"""
    if score < 2:
        return "Very Weak - This password is extremely vulnerable to attacks"
    elif score < 3:
        return "Weak - This password needs significant improvement"
    elif score < 5:
        return "Moderate - This password provides some security but could be stronger"
    else:
        return "Strong - This password provides good protection"

def calculate_entropy(password: str) -> float:
    """Calculate password entropy (bits of randomness)"""
    char_set_size = 0
    if re.search(r"[a-z]", password): char_set_size += 26
    if re.search(r"[A-Z]", password): char_set_size += 26
    if re.search(r"[0-9]", password): char_set_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): char_set_size += 32
    
    entropy = math.log2(char_set_size ** len(password)) if char_set_size > 0 else 0
    return round(entropy, 2)

def copy_to_clipboard(text: str) -> None:
    """Copy text to clipboard"""
    pyperclip.copy(text) # type: ignore

def get_time_to_crack(entropy: float) -> str:
    """Estimate time to crack based on entropy"""
    if entropy < 28:
        return "Instant"
    elif entropy < 36:
        return "Minutes"
    elif entropy < 60:
        return "Hours"
    elif entropy < 128:
        return "Months"
    else:
        return "Many years"

def main():
    st.set_page_config(
        page_title="Password Strength Meter",
        page_icon="🔒",
        layout="centered"
    )
    
    # Additional CSS
    st.markdown("""
        <style>
        .stProgress > div > div > div > div {
            background-image: linear-gradient(to right, #ff0000, #ffa500, #ffff00, #008000);
        }
        .password-generator {
            background-color: #f0f2f6;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .entropy-meter {
            font-size: 1.2em;
            margin: 10px 0;
        }
        </style>
        """, unsafe_allow_html=True)
    
    st.title("🔒 Password Strength Meter")
    st.write("Check how strong your password is!")
    
    # Password Generator Section
    st.markdown("<div class='password-generator'>", unsafe_allow_html=True)
    st.subheader("Password Generator")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        password_length = st.slider("Password Length", 12, 32, 16)
    with col2:
        st.write("")
        st.write("")
        generate_button = st.button("Generate Password")
    
    if generate_button:
        generated_password = generate_password(password_length)
        st.code(generated_password, language=None)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.info("Generated password meets all security requirements!") 
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Password Checker Section
    col1, col2 = st.columns([3, 1])
    with col1:
        password = st.text_input(
            "Enter your password",
            type="default" if st.session_state.get('password_visible', False) else "password"
        )
    with col2:
        st.write("")
        st.write("")
        if st.checkbox("Show password"):
            st.session_state.password_visible = not st.session_state.get('password_visible', False)
    
    if password:
        score, feedback, entropy = check_password_strength(password)
        
        # Calculate percentage for progress bar
        strength_percentage = (score / 6) * 100
        
        # Display progress bar
        st.progress(strength_percentage / 100)
        
        # Display strength text and description
        color = get_password_score_color(score)
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown(f"<h3 style='color: {color}'>Password Strength: {score}/6</h3>", 
                       unsafe_allow_html=True)
            st.markdown(f"<p style='color: {color}'><em>{get_strength_description(score)}</em></p>",
                       unsafe_allow_html=True)
        with col2:
            st.markdown("<div class='entropy-meter'>", unsafe_allow_html=True)
            st.metric("Entropy (bits)", entropy)
            st.markdown("</div>", unsafe_allow_html=True)
        
        # Display crack time estimate
        st.info(f"⏱️ Estimated time to crack: {get_time_to_crack(entropy)}")
        
        # Add character distribution visualization
        st.subheader("Password Analysis Visualization")
        st.plotly_chart(create_password_visualization(password))
        
        # Suggest stronger password if score is low
        if score < 4:
            suggested = suggest_similar_strong_password(password)
            st.warning("💡 Suggested stronger alternative: " + suggested)
        
        # Add password strength timeline
        with st.expander("📈 Password Strength Timeline"):
            dates = [datetime.now() - timedelta(days=x) for x in range(5)]
            strengths = [random.randint(60, 100) for _ in range(5)]  # Example data
            
            timeline_fig = go.Figure()
            timeline_fig.add_trace(go.Scatter(x=dates, y=strengths, mode='lines+markers'))
            timeline_fig.update_layout(
                title="Password Strength History",
                xaxis_title="Date",
                yaxis_title="Strength Score",
                height=300
            )
            st.plotly_chart(timeline_fig)
        
        # Add password categories
        categories = {
            'Length': len(password) / 32 * 100,
            'Complexity': score / 6 * 100,
            'Uniqueness': len(set(password)) / len(password) * 100,
            'Entropy': min(entropy / 128 * 100, 100)
        }
        
        # Create radar chart
        radar_fig = go.Figure()
        radar_fig.add_trace(go.Scatterpolar(
            r=list(categories.values()),
            theta=list(categories.keys()),
            fill='toself'
        ))
        radar_fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=False,
            title="Password Strength Categories"
        )
        st.plotly_chart(radar_fig)
        
        # Display feedback
        st.subheader("Password Analysis:")
        for item in feedback:
            st.write(item)
        
        # Security recommendations
        st.subheader("Security Tips:")
        st.info("""
        - Use a combination of uppercase and lowercase letters
        - Include numbers and special characters
        - Make your password at least 12 characters long
        - Avoid using personal information
        - Use different passwords for different accounts
        - Consider using a password manager
        - Enable two-factor authentication when possible
        - Avoid using keyboard patterns (e.g., qwerty)
        - Don't use palindromes or repeated sequences
        """)
        
        # Additional Resources
        with st.expander("📚 Learn More About Password Security"):
            st.markdown("""
            - [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
            - [Have I Been Pwned](https://haveibeenpwned.com/)
            - [Password Manager Recommendations](https://www.privacytools.io/software/passwords/)
            """)

        # Add additional statistics
        with st.expander("📊 Detailed Statistics"):
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Character Types", len(set(password)))
                st.metric("Unique Characters %", f"{(len(set(password)) / len(password) * 100):.1f}%")
            with col2:
                st.metric("Length Score %", f"{(len(password) / 32 * 100):.1f}%")
                st.metric("Pattern Score %", f"{(score / 6 * 100):.1f}%")

if __name__ == "__main__":
    main()