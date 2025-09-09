#!/usr/bin/env python3
"""
Test Font Loading Across All ThreatX Pages
"""

import requests
import re
from bs4 import BeautifulSoup

def test_font_loading():
    """Test font loading across all ThreatX pages"""
    
    base_url = "http://localhost:5000"
    
    print("🔤 Testing Font Loading Across ThreatX Pages")
    print("=" * 60)
    
    # Pages to test
    test_pages = [
        {
            "name": "Main Dashboard",
            "url": f"{base_url}/",
            "expected_fonts": ["Inter", "Roboto", "Source Sans Pro"]
        },
        {
            "name": "Health Check",
            "url": f"{base_url}/health",
            "expected_fonts": ["Inter", "Roboto", "Source Sans Pro"]
        },
        {
            "name": "Statistics Dashboard",
            "url": f"{base_url}/api/threat-statistics",
            "expected_fonts": ["Inter", "Roboto", "Source Sans Pro"]
        }
    ]
    
    all_tests_passed = True
    
    for page in test_pages:
        print(f"\n🔍 Testing: {page['name']}")
        print("-" * 40)
        
        try:
            response = requests.get(page['url'], timeout=10)
            response.raise_for_status()
            
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for font links in head
            font_links = soup.find_all('link', href=re.compile(r'fonts\.googleapis\.com|font'))
            print(f"📋 Font Links Found: {len(font_links)}")
            
            for link in font_links:
                href = link.get('href', '')
                if 'fonts.googleapis.com' in href:
                    print(f"  ✅ Google Fonts: {href}")
            
            # Check for font-family in CSS
            style_tags = soup.find_all('style')
            font_families_found = []
            
            for style in style_tags:
                css_content = style.string
                if css_content:
                    # Find font-family declarations
                    font_family_matches = re.findall(r'font-family:\s*([^;]+)', css_content, re.IGNORECASE)
                    for match in font_family_matches:
                        font_families_found.append(match.strip())
            
            # Check for expected fonts
            print(f"📝 Font Families Found: {len(set(font_families_found))}")
            
            expected_found = 0
            for expected_font in page['expected_fonts']:
                font_found = any(expected_font in family for family in font_families_found)
                if font_found:
                    print(f"  ✅ {expected_font}: Found")
                    expected_found += 1
                else:
                    print(f"  ❌ {expected_font}: Missing")
            
            # Check for font loading attributes
            preconnect_links = soup.find_all('link', rel='preconnect')
            print(f"⚡ Preconnect Links: {len(preconnect_links)}")
            
            for link in preconnect_links:
                href = link.get('href', '')
                if 'fonts.googleapis.com' in href or 'fonts.gstatic.com' in href:
                    print(f"  ✅ Preconnect: {href}")
            
            # Check for font display swap
            font_display_swap = 'display=swap' in html_content
            print(f"🔄 Font Display Swap: {'✅ Enabled' if font_display_swap else '❌ Missing'}")
            
            # Check for fallback fonts
            fallback_fonts = ['Arial', 'sans-serif', 'Helvetica', 'system-ui']
            fallback_found = any(fallback in html_content for fallback in fallback_fonts)
            print(f"🛡️ Fallback Fonts: {'✅ Present' if fallback_found else '❌ Missing'}")
            
            # Overall assessment
            font_score = (
                (expected_found / len(page['expected_fonts'])) * 30 +  # 30 points for expected fonts
                (len(font_links) > 0) * 20 +  # 20 points for font links
                (len(preconnect_links) > 0) * 20 +  # 20 points for preconnect
                font_display_swap * 15 +  # 15 points for display swap
                fallback_found * 15  # 15 points for fallbacks
            )
            
            print(f"📊 Font Loading Score: {font_score:.1f}/100")
            
            if font_score >= 80:
                print("✅ PASS: Font loading looks good!")
            elif font_score >= 60:
                print("⚠️ PARTIAL: Font loading needs improvement")
                all_tests_passed = False
            else:
                print("❌ FAIL: Font loading has significant issues")
                all_tests_passed = False
                
        except Exception as e:
            print(f"❌ Error testing {page['name']}: {e}")
            all_tests_passed = False
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📋 SUMMARY")
    print(f"{'='*60}")
    
    if all_tests_passed:
        print("✅ All font loading tests PASSED!")
        print("🎉 Fonts should be visible across all ThreatX pages")
    else:
        print("⚠️ Some font loading issues detected")
        print("💡 Check the detailed results above for specific issues")
    
    print(f"\n🔗 Test completed. Visit pages to verify visually:")
    for page in test_pages:
        print(f"  • {page['name']}: {page['url']}")

if __name__ == "__main__":
    try:
        # Test if server is running
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ ThreatX server is running\n")
            test_font_loading()
        else:
            print("❌ ThreatX server is not responding properly")
    except requests.ConnectionError:
        print("❌ Cannot connect to ThreatX server. Please start it with: python test_server.py")
    except Exception as e:
        print(f"❌ Error: {e}")