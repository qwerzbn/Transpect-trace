// Regenerate template.pptx with pptxgenjs 4.0.1.
// This is an internal single-slide parser fixture, not a presentation.
const path = require('path');
const fs = require('fs');
const JSZip = require('jszip');
const pptxgen = require('pptxgenjs');
const presentation = new pptxgen();
presentation.layout = 'LAYOUT_WIDE';
const slide = presentation.addSlide();
slide.addText('SYNTHETIC_DLP_PAYLOAD', {
  x: 1, y: 1, w: 10, h: 1, fontFace: 'Arial', fontSize: 20,
  margin: 0, breakLine: false,
});
async function main() {
  const fileName = path.join(__dirname, 'template.pptx');
  await presentation.writeFile({fileName});
  const zip = await JSZip.loadAsync(fs.readFileSync(fileName));
  const fixedDate = new Date('1980-01-01T00:00:00Z');
  for (const entry of Object.values(zip.files)) entry.date = fixedDate;
  const core = await zip.file('docProps/core.xml').async('string');
  zip.file('docProps/core.xml',
    core.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g, '2000-01-01T00:00:00Z'),
    {date: fixedDate});
  fs.writeFileSync(fileName, await zip.generateAsync({
    type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: {level: 6},
  }));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
