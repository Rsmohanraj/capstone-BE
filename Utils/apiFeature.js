class APIFeatures{
    constructor(query, queryString){
        this.query = query;
        this.queryString = queryString;
    }
    search(){
        let keyword = this.queryString.keyword ?{
            name:{
                $regex:this.queryString.keyword,
                $options:'i'
            }
        }:{};

        this.query = this.query.find({...keyword});
        return this;
    }
    filter(){
        const queryString = {...this.queryString};


        //removing fields query//..
        const removeFields = ['keyword','limit', 'page'];
        removeFields.forEach(field => delete queryString[field]);

     let queryStr = JSON.stringify(queryString);
      queryStr = queryStr = queryStr.replace(/\b(gte|gt|lt|lte)/g, match => `$${match}`);

      
        this.query.find(JSON.parse(queryStr));
        return this;
    }
    paginate(resPerPage){
        const currentPage = Number (this.queryString.page) || 1;
        const skip =resPerPage * (currentPage - 1)
        this.query.limit(resPerPage).skip(skip);
        return this;
    } 
    
}

module.exports = APIFeatures;