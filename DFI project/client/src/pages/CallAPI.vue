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
          @click="getOutS11">
          Search
        </button>
        <br>
        <br>
        <p class="text-danger">
            {{loadingStatus}}
        </p>

        <table id="outS11" class='text_left'>
        <thead>
          <tr>
            <th v-for="key_ in Object.keys(outS11[0])" :key="key_">{{key_}}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in outS11" :key="row.IP">
            <td>{{row["Domain"]}}</td>
            <td>{{row["IP"]}}</td>
            <td>{{row["ISP"]}}</td>
            <td>{{row["Record Type"]}}</td>
            <td>{{row["hostname"]}}</td>
          </tr>
        </tbody>
        </table>
      
      </div>
    </div> 
</template>
<script>
import getOutput from '@/services/getOutput'
export default {
  data() {
    return {
      outS11: [
        {"Domain": 'domain', "IP":'ip', "ISP":'isp', "Record Type":'record type', "hostname":'hostname'}
      ],
      entityName: '',
      searchDomain: '',
      keyword:'',
      loadingStatus: 'Please click search to start searching DFI data'
    };
  },
  methods:{
    async getOutS11(){
      this.loadingStatus = "Working on output 11..."
      const response = await getOutput.getOutS11({
        entityName: this.entityName,
        searchDomain: this.searchDomain,
        keyword: this.keyword
      })
      this.outS11 = response.data['outS11']
      this.outS11Columns = Object.keys(outS11[0])
    }
  }
};
</script>
<style>
table {
  font-family: 'Open Sans', sans-serif;
  width: 750px;
  border-collapse: collapse;
  border: 3px solid #44475C;
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
