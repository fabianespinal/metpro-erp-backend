from fpdf import FPDF

def add_footer_with_signature(pdf: FPDF):
    # Register cursive font (safe to call once per document)
    pdf.add_font("GreatVibes", "", "app/fonts/GreatVibes-Regular.ttf", uni=True)

    pdf.set_font('Arial', '', 7)
    pdf.set_text_color(100, 100, 100)

    sig_y = pdf.get_y()

    # SIGNATURE TEXT (Centered above "Autorizado Por")
    pdf.set_xy(20, sig_y + 5)
    pdf.set_font("GreatVibes", "", 20)  # cursive signature font
    pdf.set_text_color(60, 60, 60)
    pdf.cell(60, 8, "Fabian Espiga", 0, 0, 'C')

    # LEFT SIDE: Autorizado Por
    pdf.set_font('Arial', '', 7)
    pdf.set_text_color(100, 100, 100)
    pdf.set_xy(20, sig_y + 15)
    pdf.set_draw_color(180, 180, 180)
    pdf.line(20, sig_y + 15, 80, sig_y + 15)
    pdf.set_xy(20, sig_y + 16)
    pdf.cell(60, 4, 'Autorizado Por', 0, 0, 'C')

    # RIGHT SIDE: Firma Cliente
    pdf.set_xy(130, sig_y + 15)
    pdf.line(130, sig_y + 15, 190, sig_y + 15)
    pdf.set_xy(130, sig_y + 16)
    pdf.cell(60, 4, 'Firma Cliente', 0, 0, 'C')