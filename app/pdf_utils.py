def add_footer_with_signature(pdf):
    # Load font with fallback for Render
    try:
        pdf.add_font("GreatVibes", "", "app/fonts/GreatVibes-Regular.ttf", uni=True)
    except:
        pdf.add_font("GreatVibes", "", "backend/app/fonts/GreatVibes-Regular.ttf", uni=True)

    # Ensure signature is not off-page
    if pdf.get_y() > 240:
        pdf.set_y(240)

    pdf.set_font('Arial', '', 7)
    pdf.set_text_color(100, 100, 100)

    sig_y = pdf.get_y()

    # Signature text
    pdf.set_xy(20, sig_y - 5)  # moved up for safety
    pdf.set_font("GreatVibes", "", 20)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(60, 8, "Karmary Mata", 0, 0, 'C')

    # Left line
    pdf.set_font('Arial', '', 7)
    pdf.set_text_color(100, 100, 100)
    pdf.set_xy(20, sig_y + 5)
    pdf.set_draw_color(180, 180, 180)
    pdf.line(20, sig_y + 5, 80, sig_y + 5)
    pdf.set_xy(20, sig_y + 6)
    pdf.cell(60, 4, 'Autorizado Por', 0, 0, 'C')

    # Right line
    pdf.set_xy(130, sig_y + 5)
    pdf.line(130, sig_y + 5, 190, sig_y + 5)
    pdf.set_xy(130, sig_y + 6)
    pdf.cell(60, 4, 'Firma Cliente', 0, 0, 'C')