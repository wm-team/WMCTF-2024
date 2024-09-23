/* Memory Storage */

const Storage = {
    account: new Map(), // uid -> { password, role }
    submission: new Map() // uuid -> { content, author, ts }
}

export default Storage;