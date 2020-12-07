<template>
    <div class="row">
      <div class="text-left">
        <input 
          type="entityName" 
          name="entityName" 
          v-model="entityName"
          placeholder="Entity Name"/>
        <br>
        <br>
        <input 
          type="searchDomain" 
          name="searchDomain" 
          v-model="searchDomain"
          placeholder="Search domain"/>
        <br>
        <br>
        <input 
          type="keyword" 
          name="keyword" 
          v-model="keyword"
          placeholder="Keyword"/>
        <br>
        <br>
        <button
          type="info"
          round
          @click="getOutput">
          Search
        </button>
        <br>
        <br>
        <p class="text-danger">
            {{loadingStatus}}
        </p>  

        <p class="text-info">
            OutS11
        </p>
        <div class="scroll">
          <table id="outS11" class='text_left'>
          <thead>
            <tr>
              <th v-for="(key_, index) in Object.keys(outS11[0])" :key="index">{{key_}}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, index) in outS11" :key="index">
              <td v-for="(key_, index) in Object.keys(outS11[0])" :key="index">{{row[key_]}}</td>
            </tr>
          </tbody>
          </table>
        </div>

        <p class="text-info">
                OutS12
          </p>
        <div class="scroll">
          <table id="outS12" class='text_left'>
          <thead>
            <tr>
              <th v-for="(key_, index) in Object.keys(outS12[0])" :key="index">{{key_}}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, index) in outS12" :key="index">
              <td v-for="(key_, index) in Object.keys(outS12[0])" :key="index">{{row[key_]}}</td>
            </tr>
          </tbody>
          </table>
        </div>

        <p class="text-info">
                OutS13
          </p>
        <div class="scroll">
          <table id="outS13" class='text_left'>
          <thead>
            <tr>
              <th v-for="(key_, index) in Object.keys(outS13[0])" :key="index">{{key_}}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, index) in outS13" :key="index">
              <td v-for="(key_, index) in Object.keys(outS13[0])" :key="index">{{row[key_]}}</td>
            </tr>
          </tbody>
          </table>
        </div>

        <p class="text-info">
          {{tempStr}}
        </p>   
      </div>
    </div> 
</template>
<script>
import getOutput from '@/services/getOutput'
export default {
  data() {
    return {
      outS11: [
        {"col 1": '[row 1 col 1]', "col 2":'[row 1 col 2]', "col 3":'[row 1 col 3]', "col 4":'[row 1 col 4]'}
      ],
      outS12: [
        {"col 1": '[row 1 col 1]', "col 2":'[row 1 col 2]', "col 3":'[row 1 col 3]', "col 4":'[row 1 col 4]'}
      ],
      outS13: [
        {"col 1": '[row 1 col 1]', "col 2":'[row 1 col 2]', "col 3":'[row 1 col 3]', "col 4":'[row 1 col 4]'}
      ],
      entityName: '',
      searchDomain: '',
      keyword:'',
      loadingStatus: 'Please click search to start searching DFI data',
      tempStr:''
    };
  },
  methods:{
    async getOutput(){
      this.loadingStatus = "Calling the APIs"
      const response = await getOutput.getOutput({
        entityName: this.entityName,
        searchDomain: this.searchDomain,
        keyword: this.keyword
      })
      this.outS11 = response.data['outS11']
      this.outS12 = response.data['outS12']
      this.outS13 = response.data['outS13']
      this.tempStr = response.data['temp']
    }
  }
};
</script>
<style>
.scroll{
  width:3000px;
  max-height:500px;
  overflow: scroll;
  margin-bottom: 20px;
}
table {
  font-family: 'Open Sans', sans-serif;
  width: 750px;
  border-collapse: collapse;
  border: 3px solid #44475C;
  overflow: scroll;
  margin: 10px 10px 0 10px;
}

table th {
  text-transform: uppercase;
  text-align: left;
  background: #44475C;
  color: #FFF;
  padding: 8px;
  min-width: 30px;
}

table td {
  text-align: left;
  padding: 8px;
  border-right: 2px solid #7D82A8;
}
table td:last-child {
  border-right: none;
}
table tbody tr:nth-child(2n) td {
  background: #D4D8F9;
}
</style>
