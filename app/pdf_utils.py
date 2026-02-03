def add_footer_with_signature(pdf):
    # Load font with fallback for Render
    try:
        pdf.add_font("GreatVibes", "", "app/fonts/GreatVibes-Regular.ttf", uni=True)
    except:
        pdf.add_font("GreatVibes", "", "backend/app/fonts/GreatVibes-Regular.ttf", uni=True)

    # Capture current Y position safely
    y = pdf.get_y()

    # If content is too close to the bottom, move up
    if y > 220:
        y = 220
        pdf.set_y(y)

    # Signature text (cursive)
    pdf.set_xy(20, y + 5)
    pdf.set_font("GreatVibes", "", 20)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(60, 8, "Karmary Mata", 0, 0, 'C')

    # Reset font for labels
    pdf.set_font('Arial', '', 7)
    pdf.set_text_color(100, 100, 100)

    # Left line + label
    pdf.set_xy(20, y + 20)
    pdf.set_draw_color(180, 180, 180)
    pdf.line(20, y + 20, 80, y + 20)
    pdf.set_xy(20, y + 21)
    pdf.cell(60, 4, 'Autorizado Por', 0, 0, 'C')

    # Right line + label
    pdf.set_xy(130, y + 20)
    pdf.line(130, y + 20, 190, y + 20)
    pdf.set_xy(130, y + 21)
    pdf.cell(60, 4, 'Firma Cliente', 0, 0, 'C')