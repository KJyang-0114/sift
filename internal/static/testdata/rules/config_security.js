// ruleid: sift.config-env-file
app.use(express.static('.env'));
// ruleid: sift.config-env-file
const file = fs.readFileSync("config/.env.production");
// ok: sift.config-env-file
const port = process.env.PORT || 3000;
// ok: sift.config-env-file
const secret = process.env.JWT_SECRET;
